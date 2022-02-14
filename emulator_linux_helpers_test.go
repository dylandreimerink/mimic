package mimic

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestLinuxHelperLookup(t *testing.T) {
	vm, emu := testEnv()

	// Make program, since we can't start a process without it
	progID, err := vm.AddProgram(&ebpf.ProgramSpec{
		Name: "pseudo",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get a process which we need as arg to the helper
	p, err := vm.NewProcess(progID, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make map to read from
	m := &LinuxArrayMap{
		Spec: &ebpf.MapSpec{
			Name:       "happy path",
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 5,
		},
	}

	// Add to VM, allocating it
	err = emu.AddMap(m)
	if err != nil {
		t.Fatal(err)
	}

	// The the memory entry of the map
	mapEntry, _ := vm.MemoryController.GetEntryByObject(m)

	// Make scratch mem to put the key, we need a pointer
	scratchMem := &PlainMemory{
		Backing: make([]byte, 16),
	}
	scratchEntry, err := vm.MemoryController.AddEntry(scratchMem, 16, "scratch")
	if err != nil {
		t.Fatal(err)
	}

	// m[1] = 2
	keyVal := 1
	valVal := 2

	// Make key and value bytes slices
	ne := GetNativeEndianness()
	key := make([]byte, 4)
	ne.PutUint32(key, uint32(keyVal))

	value := make([]byte, 4)
	ne.PutUint32(value, uint32(valVal))

	// Write Key to mem so we can give a pointer of it to the helper
	err = scratchMem.Write(0, key)
	if err != nil {
		t.Fatal(err)
	}

	// Set the value in the map
	err = m.Update(key, value, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Set R1 to map ptr, R2 to key pointer
	p.Registers.R1 = uint64(mapEntry.Addr)
	p.Registers.R2 = uint64(scratchEntry.Addr)

	err = linuxHelperMapLookupElem(p)
	if err != nil {
		t.Fatal(err)
	}

	if int64(p.Registers.R0) < 0 {
		t.Fatalf("helper returned %d", p.Registers.R0)
	}

	// Get entry for return addr (is the value memory of the map)
	entry, off, found := vm.MemoryController.GetEntry(uint32(p.Registers.R0))
	if !found {
		t.Fatal("return value not found in memory controller")
	}

	vmmem, ok := entry.Object.(VMMem)
	if !ok {
		t.Fatal("return value not ptr to VMMem")
	}

	// Read memory
	ret, err := vmmem.Load(off, asm.Word)
	if err != nil {
		t.Fatal(err)
	}
	// Gotten value should be equal to the value we set
	if ret != uint64(valVal) {
		t.Fatalf("got %d, expected %d", ret, valVal)
	}
}

// TODO make test for double map pointer lookup
