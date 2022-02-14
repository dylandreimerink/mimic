package mimic

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestLinuxPerCPUArray(t *testing.T) {
	emu := NewLinuxEmulator()
	vm := NewVM(VMOptEmulator(emu), VMOptSetvCPUs(2))

	m := &LinuxPerCPUArrayMap{
		Spec: &ebpf.MapSpec{
			Name:       "per-cpu-array",
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 5,
		},
	}

	// Add to emulator, allocating it
	err := emu.AddMap(m)
	if err != nil {
		t.Fatal(err)
	}

	const CPU0 = 0
	const CPU1 = 1

	ne := GetNativeEndianness()

	keyVal := uint32(1)
	key := make([]byte, 4)
	ne.PutUint32(key, keyVal)

	valValCPU0 := uint32(2)
	valueCPU0 := make([]byte, 4)
	ne.PutUint32(valueCPU0, valValCPU0)

	valValCPU1 := uint32(3)
	valueCPU1 := make([]byte, 4)
	ne.PutUint32(valueCPU1, valValCPU1)

	err = m.Update(key, valueCPU0, 0, CPU0)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Update(key, valueCPU1, 0, CPU1)
	if err != nil {
		t.Fatal(err)
	}

	valPtrCPU0, err := m.Lookup(key, CPU0)
	if err != nil {
		t.Fatal(err)
	}

	valPtrCPU1, err := m.Lookup(key, CPU1)
	if err != nil {
		t.Fatal(err)
	}

	valEntryCPU0, off, found := vm.MemoryController.GetEntry(valPtrCPU0)
	if !found {
		t.Fatal("entry not found")
	}

	vmmem, ok := valEntryCPU0.Object.(VMMem)
	if !ok {
		t.Fatal("not VM-mem")
	}

	lookupValCPU0, err := vmmem.Load(off, asm.Word)
	if err != nil {
		t.Fatal(err)
	}

	if lookupValCPU0 != uint64(valValCPU0) {
		t.Fatalf("expected %d, got %d", valValCPU0, lookupValCPU0)
	}

	valEntryCPU1, off, found := vm.MemoryController.GetEntry(valPtrCPU1)
	if !found {
		t.Fatal("entry not found")
	}

	vmmem, ok = valEntryCPU1.Object.(VMMem)
	if !ok {
		t.Fatal("not VM-mem")
	}

	lookupValCPU1, err := vmmem.Load(off, asm.Word)
	if err != nil {
		t.Fatal(err)
	}

	if lookupValCPU1 != uint64(valValCPU1) {
		t.Fatalf("expected %d, got %d", valValCPU1, lookupValCPU1)
	}
}
