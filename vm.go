package mimic

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// VMSettings are the actual settings of the VM, VMOpt's can change an instance of these settings.
type VMSettings struct {
	Emulator Emulator
	// Size of the stack in bytes
	StackFrameSize int
	// Number of stack frames (max call depth of BPF-to-BPF calls)
	StackFrameCount int
	// Number of vCPU's, processes can't have a CPUID higher or equal to this number
	VirtualCPUs int
}

// VMOpt is a option which can be used during the creation of a VM with the NewVM function
type VMOpt func(*VMSettings)

// VMOptEmulator is used to assign an Emulator to a VM
func VMOptEmulator(e Emulator) VMOpt {
	return func(v *VMSettings) {
		v.Emulator = e
	}
}

// VMOptSetvCPUs explicitly sets the amount of virtual CPUs of the VM
func VMOptSetvCPUs(vCPUs int) VMOpt {
	return func(v *VMSettings) {
		v.VirtualCPUs = vCPUs
	}
}

// VM is the eBPF virtual machine
type VM struct {
	programsMu sync.RWMutex
	programs   []*ebpf.ProgramSpec

	MemoryController MemoryController

	settings    VMSettings
	processPool processPool
}

// NewVM create a new eBPF virtual machine from the given options.
func NewVM(opts ...VMOpt) *VM {
	vm := &VM{
		settings: VMSettings{
			// If emulator is nil, no helper functions can be used
			Emulator: nil,
			// Default to the stack frame size used in linux
			StackFrameSize: 256,
			// Default to the stack frame count used in linux
			StackFrameCount: 8,
			// Default to the number of CPUs of the host
			VirtualCPUs: runtime.NumCPU(),
		},
	}
	vm.processPool.vm = vm
	for _, opt := range opts {
		opt(&vm.settings)
	}

	// Let the emulator know, it is now attached to a VM
	vm.settings.Emulator.SetVM(vm)

	return vm
}

// GetProcessPool returns the process pool of the VM
func (vm *VM) GetProcessPool() ProcessPool {
	return &vm.processPool
}

// GetPrograms returns the loaded program specs
func (vm *VM) GetPrograms() []*ebpf.ProgramSpec {
	vm.programsMu.RLock()
	defer vm.programsMu.RUnlock()

	// Make a new slice with the same pointers, so the slice content can't be changed but the programs can
	ls := make([]*ebpf.ProgramSpec, len(vm.programs))
	for i, prog := range vm.programs {
		ls[i] = prog
	}

	return ls
}

// AddProgram adds a program to the VM. Doing so will cause the VM to rewrite the program to make it ready for
// execution. On success a unique identifier for the program is returned, which can be used in calls to NewProcess
// to specify the entrypoint program.
func (vm *VM) AddProgram(prog *ebpf.ProgramSpec) (int, error) {
	vm.programsMu.Lock()
	defer vm.programsMu.Unlock()

	// Add Nop's after every DWorldLoad so indexes of the instruction match jump offsets
	nopPatched := make(asm.Instructions, 0, len(prog.Instructions))
	for _, inst := range prog.Instructions {
		nopPatched = append(nopPatched, inst)
		if inst.OpCode.IsDWordLoad() {
			nopPatched = append(nopPatched, asm.Instruction{
				OpCode: 0, // OpCode 0 is interpreted as a No-Op
			})
		}
	}
	prog.Instructions = nopPatched

	// Let the emulator rewrite the program, allowing it to populate load instruction with addresses to its custom
	// objects.
	if vm.settings.Emulator != nil {
		err := vm.settings.Emulator.RewriteProgram(prog)
		if err != nil {
			return 0, fmt.Errorf("emulator rewrite program: %w", err)
		}
	}

	// Rewrite BPF-to-BPF function call offsets, do this last since steps before may add or remove instructions, which
	// would make the offsets invalid.
	err := fixupJumpsAndCalls(prog.Instructions)
	if err != nil {
		return -1, fmt.Errorf("Error while fixing up jumps and reference calls: %w", err)
	}

	// Add the program to the memory controller
	_, err = vm.MemoryController.AddEntry(prog, 8, prog.Name)
	if err != nil {
		return -1, fmt.Errorf("Error while adding program to memory controller: %w", err)
	}

	vm.programs = append(vm.programs, prog)

	return len(vm.programs) - 1, nil
}

// this functions was copied from ebpf.fixupJumpsAndCalls and slightly modified
func fixupJumpsAndCalls(insns asm.Instructions) error {
	symbolOffsets := make(map[string]asm.RawInstructionOffset)
	for i, ins := range insns {
		if ins.Symbol() == "" {
			continue
		}

		if _, ok := symbolOffsets[ins.Symbol()]; ok {
			return fmt.Errorf("duplicate symbol %s", ins.Symbol())
		}

		symbolOffsets[ins.Symbol()] = asm.RawInstructionOffset(i)
	}

	for i, ins := range insns {
		if ins.Reference() == "" {
			continue
		}

		symOffset, ok := symbolOffsets[ins.Reference()]
		switch {
		case ins.IsFunctionReference() && ins.Constant == -1:
			if !ok {
				break
			}

			insns[i].Constant = int64(symOffset - asm.RawInstructionOffset(i) - 1)
			continue

		case ins.OpCode.Class().IsJump() && ins.Offset == -1:
			if !ok {
				break
			}

			insns[i].Offset = int16(symOffset - asm.RawInstructionOffset(i) - 1)
			continue

		default:
			// no fixup needed
			continue
		}

		return fmt.Errorf(
			"%s at insn %d: symbol %q: %w",
			ins.OpCode,
			i,
			ins.Reference(),
			errors.New("unsatisfied program reference"),
		)
	}

	return nil
}

// NewProcess spawns a new process, `entrypoint` specifies the entrypoint program and `ctx` the context for the process
// which may be nil, if no context information is needed.
func (vm *VM) NewProcess(entrypoint int, ctx Context) (*Process, error) {
	vm.programsMu.RLock()
	defer vm.programsMu.RUnlock()

	if len(vm.programs) <= entrypoint {
		return nil, fmt.Errorf("no program with id '%d' is loaded", entrypoint)
	}

	process := &Process{
		VM: vm,
		Stack: PlainMemory{
			Backing: make([]byte, vm.settings.StackFrameCount*vm.settings.StackFrameSize),
		},
		Program:        vm.programs[entrypoint],
		Context:        ctx,
		EmulatorValues: make(map[interface{}]interface{}),
		cpuID:          -1,
		// Registers will start with zero values
	}

	entry, err := vm.MemoryController.AddEntry(&process.Stack, uint32(len(process.Stack.Backing)), "stack")
	if err != nil {
		return nil, fmt.Errorf("error while adding stack to memory controller: %w", err)
	}

	// R10 always starts at the end of the first stack frame
	process.Registers.R10 = uint64(entry.Addr + uint32(vm.settings.StackFrameSize))

	if process.Context != nil {
		// Load the context, will set R1-R5
		err = process.Context.Load(process)
		if err != nil {
			return process, fmt.Errorf("context load: %w", err)
		}
	}

	return process, nil
}

// Process describes an instance of a program executing, each process has its own registers and stack
type Process struct {
	// The VM in which the process runs
	VM *VM
	// The current Program
	Program *ebpf.ProgramSpec
	// Stack of this process
	Stack PlainMemory
	// Context of the process
	Context Context
	// The registers of this process
	Registers Registers
	// A values which the the emulator can use to track process specific values
	EmulatorValues map[interface{}]interface{}
	// The ID of the CPU on which the process is currently running, which might change during the course of its life
	// time depending on how the Host schedules the process. This number can, but doesn't have to reflect the actual
	// logical CPU of the host. It is initially -1 until set, negative values should be considered invalid.
	cpuID int

	// A slice of saved registers, each time we make a BPF-to-BPF function call, we have to save PC and R6-R9.
	calleeSavedRegister []Registers

	exited bool
}

// CPUID returns the current CPU ID of the process
func (p *Process) CPUID() int {
	return p.cpuID
}

// SetCPUID set the CPU ID of the process
func (p *Process) SetCPUID(id int) error {
	if id < 0 {
		return errors.New("not a valid CPU ID")
	}

	if id > p.VM.settings.VirtualCPUs {
		return fmt.Errorf(
			"vm only has %d vCPUs, max CPU ID is %d",
			p.VM.settings.VirtualCPUs,
			p.VM.settings.VirtualCPUs-1,
		)
	}

	p.cpuID = id
	return nil
}

var errInvalidProgramCount = errors.New("program counter points to non-existent instruction, bad jump of missing " +
	"exit instruction")

// Step "steps" through one program instruction. If this function returns `exited` == true, it means that the program
// has stop execution, subsequent calls to Step will be ineffective. If `err` != nil, it means that a fatal error was
// encountered and that the process can't continue execution subsequent calls to Step will be ineffective.
func (p *Process) Step() (exited bool, err error) {
	if p.exited {
		return true, fmt.Errorf("process has been terminated")
	}

	// Get current instruction as indicated by PC
	if len(p.Program.Instructions) <= p.Registers.PC {
		return false, errInvalidProgramCount
	}
	inst := p.Program.Instructions[p.Registers.PC]

	// Lookup the emulator function for the opcode of the instruction
	vmInst := instructions[inst.OpCode]
	if vmInst == nil {
		if p.VM.settings.Emulator == nil {
			return false, fmt.Errorf("unsupported eBPF op(%d) '%v' at PC(%d)", inst.OpCode, inst, p.Registers.PC)
		}

		vmInst = p.VM.settings.Emulator.CustomInstruction
	}

	// Store the program count of the current instruction
	pc := p.Registers.PC

	// Execute the instruction
	err = vmInst(inst, p)
	if err != nil {
		// If not errExit, it is a runtime error
		if err != errExit {
			p.exited = true
			return true, fmt.Errorf("inst at PC(%d): %w", pc, err)
		}

		return true, nil
	}

	// If the new PC is out of bounds
	if len(p.Program.Instructions) <= p.Registers.PC+1 {
		// reset PC so it points to the offending instruction.
		p.Registers.PC = pc
		p.exited = true

		return true, errInvalidProgramCount
	}

	// Increment the program counter
	p.Registers.PC++

	return false, nil
}

// Run runs the program until it exits, encounters a fatal error or the context is canceled/deadline expires
func (p *Process) Run(ctx context.Context) error {
	for {
		// Check the context very program instruction
		if err := ctx.Err(); err != nil {
			return err
		}

		exited, err := p.Step()
		if err != nil {
			return fmt.Errorf("process encountered a fatal error: %w", err)
		}
		if exited {
			return nil
		}
	}
}

// Cleanup any memory allocations associated with this process
func (p *Process) Cleanup() error {
	err := p.VM.MemoryController.DelEntryByObj(&p.Stack)
	var ctxErr error
	if p.Context != nil {
		ctxErr = p.Context.Cleanup(p)
	}

	if err != nil {
		return err
	}
	return ctxErr
}

// Registers describe the CPU registers of the VM
type Registers struct {
	// PC is the program counter, it keeps track of the next instruction to be executed by the current program. It is
	// a offset within the instruction slice.
	PC int

	// R0 is used as return values from helper functions, BPF-to-BPF calls and eBPF programs
	R0 uint64

	// R1-R5 are used as arguments to a functions.
	R1 uint64
	R2 uint64
	R3 uint64
	R4 uint64
	R5 uint64

	// R6-R9 are callee saved registers, when calling a helper or BPF-to-BPF function the callee will save the current
	// values of these registers and upon returning will restore them.
	R6 uint64
	R7 uint64
	R8 uint64
	R9 uint64

	// R10 contains a pointer to the end of the current stack frame, it is read-only, programs are not allowed to write
	// to this register, only copy its value and modify its copy. The frame pointer will be changed when calling into
	// a BPF-to-BPF function. Callees can pass the current frame pointer to the next function to allow that function
	// to access the frame pointer of the callee.
	R10 uint64
}

// Get returns the value fo a given `asmReg`
func (r *Registers) Get(asmReg asm.Register) uint64 {
	switch asmReg {
	case asm.R0:
		return r.R0
	case asm.R1:
		return r.R1
	case asm.R2:
		return r.R2
	case asm.R3:
		return r.R3
	case asm.R4:
		return r.R4
	case asm.R5:
		return r.R5
	case asm.R6:
		return r.R6
	case asm.R7:
		return r.R7
	case asm.R8:
		return r.R8
	case asm.R9:
		return r.R9
	case asm.R10:
		return r.R10
	default:
		panic(fmt.Sprintf("Unknown register (%s)", asmReg))
	}
}

// Set sets the value of a given `asmReg` to `value`
func (r *Registers) Set(asmReg asm.Register, value uint64) error {
	switch asmReg {
	case asm.R0:
		r.R0 = value
	case asm.R1:
		r.R1 = value
	case asm.R2:
		r.R2 = value
	case asm.R3:
		r.R3 = value
	case asm.R4:
		r.R4 = value
	case asm.R5:
		r.R5 = value
	case asm.R6:
		r.R6 = value
	case asm.R7:
		r.R7 = value
	case asm.R8:
		r.R8 = value
	case asm.R9:
		r.R9 = value
	case asm.R10:
		return errors.New("r10 is read-only")
	default:
		panic(fmt.Sprintf("Unknown register (%s)", asmReg))
	}

	return nil
}

// ProcessPool is a worker pool for processes. Once Start'ed processes can be submitted which will be ran on the workers
// each worker has its own virtual CPU ID, thus emulating an actual CPU. The processPool guarantees that no two
// processes will run with the same CPU ID, making programs which rely on that property to guard against race-conditions
// save to run. Starting the worker pool with the exact amount of logical CPUs on the host (runtime.NumCPU()) is also
// the most performant way to run eBPF programs which are non-blocking.
type ProcessPool interface {
	Enqueue(job ProcessPoolJob, noblock bool) error
	Start(backlog int) error
	Stop()
}

type processPool struct {
	jobQueue chan ProcessPoolJob
	wg       *sync.WaitGroup
	vm       *VM
}

// ProcessPoolJob is a job which can be scheduled with the process pool to be executed.
type ProcessPoolJob struct {
	// The process to be executed
	Process *Process
	// The context with which the process is to be ran. Which can be used to cancel a particular process or to set
	// a deadline to limit its resource usage. Optional, if nil context.Background() is used.
	Context context.Context
	// When the process exits or errors, instread of cleaning it up, it will be handed off to this callback which will
	// be started in its own goroutine. This can be used to process the results, but is also responsible for the process
	// cleanup. Optional, if nil, the process is cleaned up by the pool.
	Handoff func(p *Process, err error)
}

// Enqueue adds the given process to the backlog of the pool, if noblock is false, this call will block until there
// is room. If noblock is true, an error will be returned if the queue is full.
func (pp *processPool) Enqueue(job ProcessPoolJob, noblock bool) error {
	if pp.wg == nil {
		return fmt.Errorf("pool is not yet running")
	}

	if noblock {
		select {
		case pp.jobQueue <- job:
			return nil
		default:
			return fmt.Errorf("backlog is full")
		}
	}

	pp.jobQueue <- job
	return nil
}

// Start starts with worker pool, the workerCount is the amount of goroutines/workers to be spawned. The backlog is the
// amount of pending jobs before Enqueue will start blocking or given errors. The process pool will keep running
// until Stop is called on the process pool.
func (pp *processPool) Start(backlog int) error {
	if pp.wg != nil {
		return fmt.Errorf("pool is already running")
	}

	if backlog < 1 {
		return fmt.Errorf("backlog must be at least 1")
	}

	pp.wg = &sync.WaitGroup{}
	pp.jobQueue = make(chan ProcessPoolJob, backlog)

	for i := 0; i < pp.vm.settings.VirtualCPUs; i++ {
		pp.wg.Add(1)
		go pp.worker(i)
	}

	return nil
}

// Stop stops the worker pool, all pending jobs will be completed. Stop will block until all goroutines have exited.
func (pp *processPool) Stop() {
	close(pp.jobQueue)
	pp.wg.Wait()
	pp.wg = nil
}

func (pp *processPool) worker(cpuID int) {
	defer pp.wg.Done()

	for job := range pp.jobQueue {
		if job.Context == nil {
			job.Context = context.Background()
		}

		// If the context is already done by the time we are getting to the job.
		if err := job.Context.Err(); err != nil {
			pp.handoff(job, err)
			continue
		}

		// We can set it, it will never change.
		err := job.Process.SetCPUID(cpuID)
		if err != nil {
			pp.handoff(job, err)
			continue
		}

		// Run the process until it is done, or our context closes for whatever reason
		err = job.Process.Run(job.Context)
		pp.handoff(job, err)
	}
}

func (pp *processPool) handoff(job ProcessPoolJob, err error) {
	if job.Handoff != nil {
		// Start Handoff in separate goroutine so it never block this worker.
		go job.Handoff(job.Process, err)
	} else {
		//nolint // no way to get the error to the user, and we don't want to print things on the terminal.
		_ = job.Process.Cleanup()
	}
}
