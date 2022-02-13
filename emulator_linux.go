package mimic

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// LinuxEmulatorSettings are settings used by LinuxEmulator, which can be updated by
type LinuxEmulatorSettings struct {
	// The maximum amount of tailcalls a process can make, a security feature in the Linux kernel to avoid
	// infinite tailcall loops.
	MaxTailCalls int
}

// LinuxEmulatorOpts are options which can be passed to NewLinuxEmulator to modify the default settings.
type LinuxEmulatorOpts func(*LinuxEmulatorSettings)

// OptMaxTailCalls is a option to change the max amount of tailcalls a process is allowed to make
func OptMaxTailCalls(max int) LinuxEmulatorOpts {
	return func(settings *LinuxEmulatorSettings) {
		settings.MaxTailCalls = max
	}
}

var _ Emulator = (*LinuxEmulator)(nil)

// LinuxEmulator implements Emulator, and attempts to emulate all Linux specific eBPF features.
type LinuxEmulator struct {
	Maps map[string]LinuxMap

	settings LinuxEmulatorSettings
	vm       *VM
}

// NewLinuxEmulator create a new LinuxEmulator from the given options.
func NewLinuxEmulator(opts ...LinuxEmulatorOpts) *LinuxEmulator {
	emu := &LinuxEmulator{
		Maps: make(map[string]LinuxMap),
		settings: LinuxEmulatorSettings{
			MaxTailCalls: 33, // The default max in Linux
		},
	}

	for _, opt := range opts {
		opt(&emu.settings)
	}

	return emu
}

// AddMap adds a map to the emulator.
func (le *LinuxEmulator) AddMap(m LinuxMap) error {
	err := m.Init(le)
	if err != nil {
		return fmt.Errorf("map init: %w", err)
	}

	if le.Maps == nil {
		le.Maps = make(map[string]LinuxMap)
	}

	if _, found := le.Maps[m.GetSpec().Name]; found {
		// TODO how should we resolve this when maps come from two different ELF files? Loaders normally only have to
		// deal with unique names within a ELF file.
		return fmt.Errorf("map with name '%d' already exists in emulator", le.Maps[m.GetSpec().Name])
	}

	le.Maps[m.GetSpec().Name] = m

	return nil
}

// SetVM is called by VM when attaching the emulator to the VM, it allows the emulator to store a reference to the
// VM to which is is attached.
func (le *LinuxEmulator) SetVM(vm *VM) {
	le.vm = vm
}

// CallHelperFunction is called by the VM when it wan't to execute a helper function.
func (le *LinuxEmulator) CallHelperFunction(helperNr int32, p *Process) error {
	if len(linuxHelpers) <= int(helperNr) {
		return fmt.Errorf("unimplemented helper function %d", helperNr)
	}

	helper := linuxHelpers[helperNr]
	if helper == nil {
		return fmt.Errorf("unimplemented helper function %d", helperNr)
	}

	return helper(p)
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
