package mimic

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type VMSettings struct {
	Emulator        Emulator
	StackFrameSize  int
	StackFrameCount int
}

type VMOpt func(*VMSettings)

func VMOptEmulator(e Emulator) VMOpt {
	return func(v *VMSettings) {
		v.Emulator = e
	}
}

// VM is the eBPF virtual machine
type VM struct {
	programsMu sync.RWMutex
	programs   []*ebpf.ProgramSpec

	MemoryController MemoryController

	settings VMSettings
}

func NewVM(opts ...VMOpt) *VM {
	vm := &VM{
		settings: VMSettings{
			// If emulator is nil, no helper functions can be used
			Emulator: nil,
			// Default to the stack frame size used in linux
			StackFrameSize: 256,
			// Default to the stack frame count used in linux
			StackFrameCount: 8,
		},
	}
	for _, opt := range opts {
		opt(&vm.settings)
	}

	// Let the emulator know, it is now attached to a VM
	vm.settings.Emulator.SetVM(vm)

	return vm
}

// GetPrograms returns a copy the loaded program specs
func (vm *VM) GetPrograms() []*ebpf.ProgramSpec {
	vm.programsMu.RLock()
	defer vm.programsMu.RUnlock()

	// We don't want to return our slice since it would become modifyable outside of the control of the mutex
	// So return a copy
	ls := make([]*ebpf.ProgramSpec, len(vm.programs))
	for i, prog := range vm.programs {
		ls[i] = prog.Copy()
	}

	return ls
}

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

	symbolOffsets, err := prog.Instructions.SymbolOffsets()
	if err != nil {
		return 0, fmt.Errorf("prog instruction symbol offsets: %w", err)
	}

	for refName, callOffset := range prog.Instructions.ReferenceOffsets() {
		refOffset, ok := symbolOffsets[refName]
		if !ok {
			continue
		}

		for _, off := range callOffset {
			inst := prog.Instructions[off]
			if !inst.IsFunctionCall() {
				// Ignore other references(maps), those need to be handled by the emulator
				continue
			}

			prog.Instructions[off].Constant = int64(refOffset - off)
		}
	}

	vm.programs = append(vm.programs, prog)

	return len(vm.programs) - 1, nil
}

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
		Program: vm.programs[entrypoint],
		Context: ctx,
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
	// A slice of saved registers, each time we make a BPF-to-BPF function call, we have to save PC and R6-R9.
	calleeSavedRegister []Registers

	exited bool
}

var errInvalidProgramCount = errors.New("program counter points to non-existent instruction, bad jump of missing " +
	"exit instruction")

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
		return false, fmt.Errorf("unsupported eBPF op(%d) '%v' at PC(%d)", inst.OpCode, inst, p.Registers.PC)
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
