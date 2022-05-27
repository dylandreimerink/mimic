package mimic

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
)

func TestEmulatedHashMapLRU(t *testing.T) {
	emu := &LinuxEmulator{}
	NewVM(VMOptEmulator(emu))

	m := &LinuxLRUHashMap{
		Spec: &ebpf.MapSpec{
			Name:       "LRU map",
			Type:       ebpf.LRUHash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 5,
		},
	}

	err := emu.AddMap("LRU map", m)
	if err != nil {
		t.Fatal(err)
	}

	k1 := []byte{0, 0, 0, 1}
	k2 := []byte{0, 0, 0, 2}
	k3 := []byte{0, 0, 0, 3}
	k4 := []byte{0, 0, 0, 4}
	k5 := []byte{0, 0, 0, 5}
	k6 := []byte{0, 0, 0, 6}

	v11 := []byte{0, 0, 0, 11}
	v12 := []byte{0, 0, 0, 12}
	v13 := []byte{0, 0, 0, 13}
	v14 := []byte{0, 0, 0, 14}
	v15 := []byte{0, 0, 0, 15}
	v16 := []byte{0, 0, 0, 16}

	// Add 5 values, filling the map
	err = m.Update(k1, v11, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Update(k2, v12, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Update(k3, v13, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Update(k4, v14, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Update(k5, v15, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Key 1 was added first, so it is least recently used.

	// Lookup 1 and 2, no 3 should be least recently used
	_, err = m.Lookup(k1, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Lookup(k2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Insert a sixth element, which should overwrite 3
	err = m.Update(k6, v16, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	kat := func(idx int) []byte {
		e := m.usageList.Front()
		for i := 0; i < idx; i++ {
			e = e.Next()
		}
		return e.Value.([]byte)
	}

	// 6 should be the most recent since it was added last
	if !bytes.Equal(kat(0), k6) {
		t.Fatal("usage list 0 != k6")
	}
	// 2 should be second due to the most recent lookup
	if !bytes.Equal(kat(1), k2) {
		t.Fatal("usage list 1 != k2")
	}
	// 1 should be third due to the lookup
	if !bytes.Equal(kat(2), k1) {
		t.Fatal("usage list 2 != k1")
	}
	if !bytes.Equal(kat(3), k5) {
		t.Fatal("usage list 3 != k5")
	}
	if !bytes.Equal(kat(4), k4) {
		t.Fatal("usage list 4 != k4")
	}
}
