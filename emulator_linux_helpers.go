package mimic

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// HelperFunction is a function defined in Go which can be invoked by the eBPF VM via the Call instruction.
// The emulator has a lookup map which maps a particular number to a helper function. Helper functions are used as a
// interface between the sandboxed eBPF VM and the Emulator/Host/Outside world. Helper functions are responsible for
// security checks and should implement policies or other forms of limitations to guarantee that eBPF code can't be used
// for malicious purposes.
//
// Helper functions are called with eBPF calling convention, meaning R1-R5 are arguments, and R0 is the return value.
// Errors returned by the helper are considered fatal for the process, are passed to the process and will result in it
// aborting. Recoverable errors/graceful errors should be returned to the VM via the R0 register and a helper func
// specific contract.
type HelperFunction func(p *Process) error

var linuxHelpers = []HelperFunction{
	0:                       nil, // 0 is not a valid helper function
	asm.FnMapLookupElem:     linuxHelperMapLookupElem,
	asm.FnMapUpdateElem:     linuxHelperMapUpdateElem,
	asm.FnMapDeleteElem:     linuxHelperMapDeleteElem,
	asm.FnKtimeGetNs:        linuxHelperGetKTimeNs,
	asm.FnGetPrandomU32:     linuxHelperGetPRandomU32,
	asm.FnGetSmpProcessorId: linuxHelperGetSmpProcessorID,
	asm.FnTailCall:          linuxHelperTailcall,
	asm.FnKtimeGetBootNs:    linuxHelperGetKTimeNs,
	asm.FnKtimeGetCoarseNs:  linuxHelperGetKTimeNs,
}

func syscallErr(errNo syscall.Errno) uint64 {
	return uint64(int64(0) - int64(errNo))
}

func regToMap(p *Process, reg asm.Register) (LinuxMap, error) {
	// Deref the map pointer to get the actual map object
	entry, off, found := p.VM.MemoryController.GetEntry(uint32(p.Registers.Get(reg)))
	if !found {
		return nil, fmt.Errorf("invalid map pointer in %s, can't find entry in memory controller", reg)
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
				return nil, fmt.Errorf("invalid doubel map pointer in %s, can't find entry in memory controller", reg)
			}

			lm, ok = entry.Object.(LinuxMap)
			if !ok {
				return nil, fmt.Errorf("%s doesn't contain pointer or dubbel pointer to a LinuxMap", reg)
			}
		} else {
			return nil, fmt.Errorf("%s doesn't contain pointer to a LinuxMap", reg)
		}
	}

	return lm, nil
}

func derefMapKey(p *Process, register uint64, size uint32) ([]byte, error) {
	addr := uint32(register)

	// Deref the key to get the actual key value
	keyMem, off, found := p.VM.MemoryController.GetEntry(addr)
	if !found {
		return nil, fmt.Errorf("key unknown to memory controller: 0x%x", addr)
	}

	vmMem, ok := keyMem.Object.(VMMem)
	if !ok {
		return nil, fmt.Errorf("key points to non-vm memory: 0x%x", addr)
	}

	// Read x bytes at the given key pointer, x being the key size indicated by the map spec
	keyVal := make([]byte, size)
	err := vmMem.Read(off, keyVal)
	if err != nil {
		return nil, fmt.Errorf("deref key ptr: %w", err)
	}

	return keyVal, nil
}

func linuxHelperMapLookupElem(p *Process) error {
	// R1 = ptr to the map, R2 = ptr to key

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}

	keyVal, err := derefMapKey(p, p.Registers.R2, lm.GetSpec().KeySize)
	if err != nil {
		return err
	}

	valPtr, err := lm.Lookup(keyVal, p.CPUID())
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
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}

	lmu, ok := lm.(LinuxMapUpdater)
	if !ok {
		return fmt.Errorf("given LinuxMap can't be updated")
	}

	keyVal, err := derefMapKey(p, p.Registers.R2, lm.GetSpec().KeySize)
	if err != nil {
		return err
	}

	// Deref the value to get the actual value value
	value := uint32(p.Registers.R3)
	valMem, off, found := p.VM.MemoryController.GetEntry(value)
	if !found {
		return fmt.Errorf("value unknown to memory controller: 0x%x", value)
	}

	vmMem, ok := valMem.Object.(VMMem)
	if !ok {
		return fmt.Errorf("value points to non-vm memory: 0x%x", value)
	}

	// Read x bytes at the given value pointer, x being the value size indicated by the map spec
	valVal := make([]byte, lm.GetSpec().ValueSize)
	err = vmMem.Read(off, valVal)
	if err != nil {
		return fmt.Errorf("deref value ptr: %w", err)
	}

	err = lmu.Update(keyVal, valVal, uint32(p.Registers.R4), p.CPUID())
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
	lm, err := regToMap(p, asm.R1)
	if err != nil {
		return err
	}
	lmd, ok := lm.(LinuxMapDeleter)
	if !ok {
		return fmt.Errorf("can't delete from given LinuxMap")
	}

	keyVal, err := derefMapKey(p, p.Registers.R2, lm.GetSpec().KeySize)
	if err != nil {
		return err
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

func linuxHelperGetKTimeNs(p *Process) error {
	// Note: this helper should subtract time the system was suspended, but we don't do that at the moment.
	// TODO can we even get access to a suspended-time-counter in userspace? Is this that critical?
	bootTime := p.VM.settings.Emulator.(*LinuxEmulator).settings.TimeOfBoot
	p.Registers.R0 = uint64(time.Since(bootTime))
	return nil
}

// bpf_get_prandom_u32
func linuxHelperGetPRandomU32(p *Process) error {
	p.Registers.R0 = uint64(p.VM.settings.Emulator.(*LinuxEmulator).rng.Uint32())
	return nil
}

// bpf_get_smp_processor_id
func linuxHelperGetSmpProcessorID(p *Process) error {
	p.Registers.R0 = uint64(p.CPUID())
	return nil
}

func linuxHelperTailcall(p *Process) error {
	// R1 = ctx, R2 = ptr to the prog array map, R3 = uint32 key

	var pastTailcalls int
	if i := p.EmulatorValues[LinuxEmuProcValKeyTailcalls]; i != nil {
		var ok bool
		pastTailcalls, ok = i.(int)
		if !ok {
			pastTailcalls = 0
		}
	}

	// If we have exceeded the configured max amount of tailcalls, deny execution of another.
	// We do this to emulate the behavior of Linux.
	if pastTailcalls >= p.VM.settings.Emulator.(*LinuxEmulator).settings.MaxTailCalls {
		p.Registers.R0 = syscallErr(syscall.EPERM)
		return nil
	}

	// Deref the map pointer to get the actual map object
	lm, err := regToMap(p, asm.R2)
	if err != nil {
		return err
	}

	if lm.GetSpec().Type != ebpf.ProgramArray || lm.GetSpec().KeySize != 4 {
		return fmt.Errorf("R1 is not a program array map")
	}

	progArr, ok := lm.(*LinuxArrayMap)
	if !ok {
		return fmt.Errorf("R1 is not a program array map")
	}

	// For the tailcall helper the key is passed directly, not as pointer
	key := make([]byte, 4)
	GetNativeEndianness().PutUint32(key, uint32(p.Registers.R3))

	// Lookup should return a pointer into the prog array values
	progAddrPtr, err := progArr.Lookup(key, p.CPUID())
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}

	// Deref the pointer to get the prog array VMMem
	entry, off, found := p.VM.MemoryController.GetEntry(progAddrPtr)
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		return fmt.Errorf("prog array lookup returned pointer to non-vm-memory")
	}

	// Get the program address from the array
	progAddr, err := vmmem.Load(off, asm.Word)
	if !ok {
		return fmt.Errorf("prog addr lookup: %w", err)
	}

	// Deref it to get the *ebpf.ProgramSpec
	entry, _, found = p.VM.MemoryController.GetEntry(uint32(progAddr))
	if !found {
		// If the address is not valid, handle it gracefully
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	prog, ok := entry.Object.(*ebpf.ProgramSpec)
	if !ok {
		// If the address resolves to something other than a program
		p.Registers.R0 = syscallErr(syscall.EINVAL)
		return nil
	}

	// Change the program
	p.Program = prog
	// Set the PC to -1, since after returning from the helper the PC is incremented, this will result in a PC of 0
	// so the next instruction to be executed is the first of the given program.
	p.Registers.PC = -1

	// Increment the tailcall count
	pastTailcalls++
	p.EmulatorValues[LinuxEmuProcValKeyTailcalls] = pastTailcalls

	return nil
}
