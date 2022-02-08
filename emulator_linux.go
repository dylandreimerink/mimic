package mimic

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

var _ Emulator = (*LinuxEmulator)(nil)

type LinuxEmulator struct {
	vm   *VM
	Maps map[string]LinuxMap
}

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

func (le *LinuxEmulator) SetVM(vm *VM) {
	le.vm = vm
}

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
					"map named '%s', isn't registed at the VM's memory controller",
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

type HelperFunction func(p *Process) error

var linuxHelpers = []HelperFunction{
	0:                   nil, // 0 is not a valid helper function
	asm.FnMapLookupElem: linuxHelperMapLookupElem,
	asm.FnMapUpdateElem: linuxHelperMapUpdateElem,
	asm.FnMapDeleteElem: linuxHelperMapDeleteElem,
}

func r1ToMap(p *Process) (LinuxMap, error) {
	// Deref the map pointer to get the actual map object
	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.R1))
	if !found {
		return nil, fmt.Errorf("invalid map pointer in R1, can't find entry in memory controller")
	}

	lm, ok := entry.Object.(LinuxMap)
	if !ok {
		// There are situations, like when using map-in-map types where we will get a double pointer to a BPF map
		// So lets attempts to dereference once more
		if vmMem, ok := entry.Object.(VMMem); ok {
			addr, err := vmMem.Load(off, asm.Word)
			if err != nil {
				return nil, fmt.Errorf("Error while attempting to deref dubbel map ptr")
			}

			entry, _, found = p.VM.MemoryController.GetEntry(uint32(addr))
			if !found {
				return nil, fmt.Errorf("invalid doubel map pointer in R1, can't find entry in memory controller")
			}

			lm, ok = entry.Object.(LinuxMap)
			if !ok {
				return nil, fmt.Errorf("R1 doesn't contain pointer or dubbel pointer to a LinuxMap")
			}
		} else {
			return nil, fmt.Errorf("R1 doesn't contain pointer to a LinuxMap")
		}
	}

	return lm, nil
}

func linuxHelperMapLookupElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key

	// Deref the map pointer to get the actual map object
	lm, err := r1ToMap(p)
	if err != nil {
		return err
	}

	// Deref the key to get the actual key value
	key := uint32(p.Registers.R2)
	keyMem, off, found := p.VM.MemoryController.GetEntry(key)
	if !found {
		return fmt.Errorf("key unknown to memory controller: 0x%x", key)
	}

	vmMem, ok := keyMem.Object.(VMMem)
	if !ok {
		return fmt.Errorf("key points to non-vm memory: 0x%x", key)
	}

	// Read x bytes at the given key pointer, x being the key size indicated by the map spec
	keyVal := make([]byte, lm.GetSpec().KeySize)
	err = vmMem.Read(off, keyVal)
	if err != nil {
		return fmt.Errorf("deref key ptr: %w", err)
	}

	valPtr, err := lm.Lookup(keyVal)
	if err != nil {
		var sysErr syscall.Errno
		if !errors.As(err, &sysErr) {
			return fmt.Errorf("LinuxMap lookup: %w", err)
		}
		p.Registers.R0 = uint64(sysErr)
		return nil
	}

	p.Registers.R0 = uint64(valPtr)

	return nil
}

func linuxHelperMapUpdateElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key, R3 = ptr to value, R4 = flags
	// Deref the map pointer to get the actual map object
	lm, err := r1ToMap(p)
	if err != nil {
		return err
	}

	lmu, ok := lm.(LinuxMapUpdater)
	if !ok {
		return fmt.Errorf("given LinuxMap can't be updated")
	}

	// Deref the key to get the actual key value
	key := uint32(p.Registers.R2)
	keyMem, off, found := p.VM.MemoryController.GetEntry(key)
	if !found {
		return fmt.Errorf("key unknown to memory controller: 0x%x", key)
	}

	vmMem, ok := keyMem.Object.(VMMem)
	if !ok {
		return fmt.Errorf("key points to non-vm memory: 0x%x", key)
	}

	// Read x bytes at the given key pointer, x being the key size indicated by the map spec
	keyVal := make([]byte, lm.GetSpec().KeySize)
	err = vmMem.Read(off, keyVal)
	if err != nil {
		return fmt.Errorf("deref key ptr: %w", err)
	}

	// Deref the value to get the actual value value
	value := uint32(p.Registers.R3)
	valMem, off, found := p.VM.MemoryController.GetEntry(value)
	if !found {
		return fmt.Errorf("value unknown to memory controller: 0x%x", key)
	}

	vmMem, ok = valMem.Object.(VMMem)
	if !ok {
		return fmt.Errorf("value points to non-vm memory: 0x%x", key)
	}

	// Read x bytes at the given value pointer, x being the value size indicated by the map spec
	valVal := make([]byte, lm.GetSpec().ValueSize)
	err = vmMem.Read(off, valVal)
	if err != nil {
		return fmt.Errorf("deref value ptr: %w", err)
	}

	err = lmu.Update(keyVal, valVal, uint32(p.Registers.R4))
	if err != nil {
		var sysErr syscall.Errno
		if !errors.As(err, &sysErr) {
			return fmt.Errorf("LinuxMap update: %w", err)
		}
		p.Registers.R0 = uint64(sysErr)
		return nil
	}

	p.Registers.R0 = 0
	return nil
}

func linuxHelperMapDeleteElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key

	// Deref the map pointer to get the actual map object
	lm, err := r1ToMap(p)
	if err != nil {
		return err
	}
	lmd, ok := lm.(LinuxMapDeleter)
	if !ok {
		return fmt.Errorf("can't delete from given LinuxMap")
	}

	// Deref the key to get the actual key value
	key := uint32(p.Registers.R2)
	keyMem, off, found := p.VM.MemoryController.GetEntry(key)
	if !found {
		return fmt.Errorf("key unknown to memory controller: 0x%x", key)
	}

	vmMem, ok := keyMem.Object.(VMMem)
	if !ok {
		return fmt.Errorf("key points to non-vm memory: 0x%x", key)
	}

	// Read x bytes at the given key pointer, x being the key size indicated by the map spec
	keyVal := make([]byte, lm.GetSpec().KeySize)
	err = vmMem.Read(off, keyVal)
	if err != nil {
		return fmt.Errorf("deref key ptr: %w", err)
	}

	err = lmd.Delete(keyVal)
	if err != nil {
		var sysErr syscall.Errno
		if !errors.As(err, &sysErr) {
			return fmt.Errorf("LinuxMap delete: %w", err)
		}
		p.Registers.R0 = uint64(sysErr)
		return nil
	}

	p.Registers.R0 = 0
	return nil
}
