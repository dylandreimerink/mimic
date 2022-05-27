package mimic

import (
	cryptoRand "crypto/rand"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// LinuxEmulatorSettings are settings used by LinuxEmulator, which can be updated by
type LinuxEmulatorSettings struct {
	// The maximum amount of tailcalls a process can make, a security feature in the Linux kernel to avoid
	// infinite tailcall loops.
	MaxTailCalls int

	// The seed used by the pseudo random number generator for the bpf_get_prandom_u32 function.
	// Is set to the current nanoseconds since system boot, but can be set to a custom value to make the the emulator
	// predictable.
	RandomSeed int64

	// The boot time of the emulator, is the boot time of the host by default, can be set so behavior is predictable.
	// Value is used to calculate time since boot for bpf_ktime_get_ns helper function.
	TimeOfBoot time.Time

	// The size of the perf event ring buffer per cpu. When allocating memory for a MAP_TYPE_PERF_EVENT_ARRAY, this
	// is the number of bytes per cpu reserved. This value is always rounded up to the nearest multiple of the
	// systems page size.
	PerfEventBufferSize int
}

// LinuxEmulatorOpts are options which can be passed to NewLinuxEmulator to modify the default settings.
type LinuxEmulatorOpts func(*LinuxEmulatorSettings)

// OptMaxTailCalls is a option to change the max amount of tailcalls a process is allowed to make
func OptMaxTailCalls(max int) LinuxEmulatorOpts {
	return func(settings *LinuxEmulatorSettings) {
		settings.MaxTailCalls = max
	}
}

// OptRngSeed sets the seed for the random number generator used for bpf_get_prandom_u32.
func OptRngSeed(seed int64) LinuxEmulatorOpts {
	return func(settings *LinuxEmulatorSettings) {
		settings.RandomSeed = seed
	}
}

var _ Emulator = (*LinuxEmulator)(nil)

// LinuxEmulator implements Emulator, and attempts to emulate all Linux specific eBPF features.
type LinuxEmulator struct {
	Maps map[string]LinuxMap

	// Random number generator, used by the bpf_get_prandom_u32 helper
	rng *rand.Rand

	settings LinuxEmulatorSettings
	vm       *VM
}

// NewLinuxEmulator create a new LinuxEmulator from the given options.
func NewLinuxEmulator(opts ...LinuxEmulatorOpts) *LinuxEmulator {
	// By default, get a random seed
	seed := make([]byte, 8)
	_, err := cryptoRand.Read(seed)
	if err != nil {
		seed = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	}

	emu := &LinuxEmulator{
		Maps: make(map[string]LinuxMap),
		settings: LinuxEmulatorSettings{
			MaxTailCalls:        33, // The default max in Linux
			RandomSeed:          int64(GetNativeEndianness().Uint64(seed)),
			TimeOfBoot:          timeOfBoot(),
			PerfEventBufferSize: os.Getpagesize(),
		},
	}

	for _, opt := range opts {
		opt(&emu.settings)
	}

	// Seed our random number generator with the default or updated seed
	//nolint // We know this is not secure, don't matter in this case
	emu.rng = rand.New(rand.NewSource(emu.settings.RandomSeed))

	return emu
}

// AddMap adds a map to the emulator.
func (le *LinuxEmulator) AddMap(name string, m LinuxMap) error {
	err := m.Init(le)
	if err != nil {
		return fmt.Errorf("map init: %w", err)
	}

	if le.Maps == nil {
		le.Maps = make(map[string]LinuxMap)
	}

	if _, found := le.Maps[name]; found {
		// TODO how should we resolve this when maps come from two different ELF files? Loaders normally only have to
		// deal with unique names within a ELF file.
		return fmt.Errorf("map with name '%d' already exists in emulator", le.Maps[name])
	}

	le.Maps[name] = m

	return nil
}

// SetVM is called by VM when attaching the emulator to the VM, it allows the emulator to store a reference to the
// VM to which is is attached.
func (le *LinuxEmulator) SetVM(vm *VM) {
	le.vm = vm
}

// CallHelperFunction is called by the VM when it wants to execute a helper function.
func (le *LinuxEmulator) CallHelperFunction(helperNr int32, p *Process) error {
	attemptReplay := len(replayableHelpers) > int(helperNr) && replayableHelpers[helperNr]
	if attemptReplay {
		var helperCalls map[string][]CapturedContextHelperCall
		cc, ok := p.Context.(*CapturedContext)
		if ok {
			helperCalls = cc.HelperCalls
		}

		var counts map[int32]int
		if callCountsInt := p.EmulatorValues["callCount"]; callCountsInt != nil {
			var ok bool
			counts, ok = callCountsInt.(map[int32]int)
			if !ok {
				return fmt.Errorf("'callCount' emulator value contains a non-map[int32]int value")
			}
		}
		if counts == nil {
			counts = make(map[int32]int)
		}

		count := counts[helperNr]

		calls := helperCalls[strconv.Itoa(int(helperNr))]
		if len(calls) > count {
			counts[helperNr] = count + 1
			p.EmulatorValues["callCount"] = counts

			call := calls[count]

			for _, result := range call.Result {
				if len(result.Data) > 0 {
					entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.Get(result.Reg)))
					if !found {
						return fmt.Errorf("register r%d isn't a pointer", result.Reg)
					}

					vmmem, ok := entry.Object.(VMMem)
					if !ok {
						return fmt.Errorf("register r%d doesn't point to vm-mem", result.Reg)
					}

					err := vmmem.Write(off, result.Data)
					if err != nil {
						// TODO set R0 to a negative number instread of erroring outright?
						return fmt.Errorf("error while writing to r%d: %w", result.Reg, err)
					}
				} else {
					err := p.Registers.Set(result.Reg, result.Scalar)
					if err != nil {
						return fmt.Errorf("set result: %w", err)
					}
				}
			}

			return nil
		}
	}

	if len(emulatedLinuxHelpers) <= int(helperNr) {
		return fmt.Errorf("unimplemented helper function %d", helperNr)
	}

	helper := emulatedLinuxHelpers[helperNr]
	if helper == nil {
		return fmt.Errorf("unimplemented helper function %d", helperNr)
	}

	return helper(p)
}

// CustomInstruction is called by the VM when it encounters a unimplemented CPU instruction, giving the emulator a
// chance to provide an implementation.
func (le *LinuxEmulator) CustomInstruction(inst asm.Instruction, process *Process) error {
	switch inst.OpCode {
	case asm.LoadAbsOp(asm.Byte), asm.LoadAbsOp(asm.Half), asm.LoadAbsOp(asm.Word), asm.LoadAbsOp(asm.DWord):
		// https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#packet-access-instructions

		// R0 = ntohl(*(u32 *) (((struct sk_buff *) R6)->data + imm32))

		// (((struct sk_buff *) R6)->data
		skbEntry, _, found := process.VM.MemoryController.GetEntry(uint32(process.Registers.R6))
		if !found {
			return fmt.Errorf("mem ctl doesn't have an entry for address '0x%08X'", uint32(process.Registers.R6))
		}
		// TODO check if we can piece together a __sk_buff from PlainMemory
		skb, ok := skbEntry.Object.(*SKBuff)
		if !ok {
			return fmt.Errorf("R6 is not a sk_buff")
		}

		// (((struct sk_buff *) R6)->data + imm32)
		addr := skb.data + uint32(inst.Constant)
		pktEntry, off, found := process.VM.MemoryController.GetEntry(addr)
		if !found {
			return fmt.Errorf("mem ctl doesn't have an entry for address '0x%08X'", addr)
		}

		vmmem, ok := pktEntry.Object.(VMMem)
		if !ok {
			return fmt.Errorf("%v is not a VMMem", pktEntry.Object)
		}

		var err error
		process.Registers.R0, err = vmmem.Load(off, inst.OpCode.Size())
		if err != nil {
			return fmt.Errorf("packet read: %w", err)
		}

		// "and R1 - R5 are clobbered."
		process.Registers.R1 = 0
		process.Registers.R2 = 0
		process.Registers.R3 = 0
		process.Registers.R4 = 0
		process.Registers.R5 = 0

		return nil

	case asm.LoadIndOp(asm.Byte), asm.LoadIndOp(asm.Half), asm.LoadIndOp(asm.Word), asm.LoadIndOp(asm.DWord):
		// https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#packet-access-instructions

		// R0 = ntohl(*(u32 *) (((struct sk_buff *) R6)->data + src_reg + imm32))

		// (((struct sk_buff *) R6)->data
		skbEntry, _, found := process.VM.MemoryController.GetEntry(uint32(process.Registers.R6))
		if !found {
			return fmt.Errorf("mem ctl doesn't have an entry for address '0x%08X'", uint32(process.Registers.R6))
		}
		// TODO check if we can piece together a __sk_buff from PlainMemory
		skb, ok := skbEntry.Object.(*SKBuff)
		if !ok {
			return fmt.Errorf("R6 is not a sk_buff")
		}

		// (((struct sk_buff *) R6)->data + src_reg + imm32)
		addr := skb.data + uint32(process.Registers.Get(inst.Src)) + uint32(inst.Constant)
		pktEntry, off, found := process.VM.MemoryController.GetEntry(addr)
		if !found {
			return fmt.Errorf("mem ctl doesn't have an entry for address '0x%08X'", addr)
		}

		vmmem, ok := pktEntry.Object.(VMMem)
		if !ok {
			return fmt.Errorf("%v is not a VMMem", pktEntry.Object)
		}

		var err error
		process.Registers.R0, err = vmmem.Load(off, inst.OpCode.Size())
		if err != nil {
			return fmt.Errorf("packet read: %w", err)
		}

		// "and R1 - R5 are clobbered."
		process.Registers.R1 = 0
		process.Registers.R2 = 0
		process.Registers.R3 = 0
		process.Registers.R4 = 0
		process.Registers.R5 = 0

		return nil
	}

	return fmt.Errorf("unsupported eBPF op(%d) '%v' at PC(%d)", inst.OpCode, inst, process.Registers.PC)
}

// RewriteProgram is called by the VM when adding a program to it. It allows us to rewrite program instructions.
// In this case we rewrite map load instructions to have the virtual addresess of the map to which the refer.
func (le *LinuxEmulator) RewriteProgram(program *ebpf.ProgramSpec) error {
	if le.Maps == nil {
		le.Maps = make(map[string]LinuxMap)
	}

	for refName, offsets := range program.Instructions.ReferenceOffsets() {
		for _, offset := range offsets {
			inst := program.Instructions[offset]
			if !inst.IsLoadFromMap() {
				// Skip non-map references, the VM will have dealt with BPF-to-BPF references already
				continue
			}

			refMap, foundMap := le.Maps[refName]
			if !foundMap {
				return fmt.Errorf(
					"program references a map named '%s', no map with that name exists in the emulator",
					refName,
				)
			}

			mapMemEntry, found := le.vm.MemoryController.GetEntryByObject(refMap)
			if !found {
				return fmt.Errorf(
					"map named '%s', isn't registered at the VM's memory controller",
					refName,
				)
			}

			// If this is a load of the address of a map
			if inst.Src == asm.PseudoMapFD {
				program.Instructions[offset].Constant = int64(mapMemEntry.Addr)
				continue
			}

			// If this is a direct load from a map.
			if inst.Src == asm.PseudoMapValue {
				// Return a specific offset into the map
				program.Instructions[offset].Constant = int64(mapMemEntry.Addr) + int64(inst.Offset)
				continue
			}

			return fmt.Errorf("unknown load from map instruction %v", inst)
		}
	}

	return nil
}

// LinuxEmuProcValKey is a enum values which is used as the key to the Process.EmulatorValues maps when a LinuxEmulator
// is used.
type LinuxEmuProcValKey int

const (
	// LinuxEmuProcValKeyTailcalls tracks the amount of tailcalls which a process has made.
	LinuxEmuProcValKeyTailcalls LinuxEmuProcValKey = iota
)

var linuxEmuProcValKeyToStr = map[LinuxEmuProcValKey]string{
	LinuxEmuProcValKeyTailcalls: "#-tailcalls",
}

func (v LinuxEmuProcValKey) String() string {
	return linuxEmuProcValKeyToStr[v]
}
