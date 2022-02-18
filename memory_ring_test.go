package mimic

import (
	"bytes"
	"testing"
)

func TestRingMemory(t *testing.T) {
	ring := RingMemory{
		Backing: make([]byte, 16),
	}

	// A byte slice to compair against
	cmp := make([]byte, 16)

	err := ring.Write(0, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	copy(cmp[0:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if !bytes.Equal(cmp, ring.Backing) {
		t.Fatalf("expected: %v, got: %v", cmp, ring.Backing)
	}

	err = ring.Write(8, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	copy(cmp[8:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if !bytes.Equal(cmp, ring.Backing) {
		t.Fatalf("expected: %v, got: %v", cmp, ring.Backing)
	}

	err = ring.Write(12, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	copy(cmp[12:], []byte{1, 2, 3, 4})
	copy(cmp, []byte{5, 6, 7, 8})
	if !bytes.Equal(cmp, ring.Backing) {
		t.Fatalf("expected: %v, got: %v", cmp, ring.Backing)
	}

	b := make([]byte, 8)
	err = ring.Read(12, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("expected: %v, got: %v", cmp, ring.Backing)
	}
}
