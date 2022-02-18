package mimic

import (
	"bytes"
	"testing"
)

func TestRingBuffer(t *testing.T) {
	rb := ringBuffer{
		backing: &RingMemory{
			Backing: make([]byte, 20),
		},
	}

	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	err := rb.Write(b)
	if err != nil {
		t.Fatal(err)
	}

	err = rb.Write(b)
	if err != nil {
		t.Fatal(err)
	}

	err = rb.Write(b)
	if err == nil {
		t.Fatal("buf full, expected an error")
	}

	t.Log(rb.Used())

	v := make([]byte, 8)
	_, err = rb.Read(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, b) {
		t.Fatalf("%v != %v", v, b)
	}

	err = rb.Write(b)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(rb)

	err = rb.Write(b)
	if err == nil {
		t.Fatal("buf full, expected an error")
	}

	_, err = rb.Read(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, b) {
		t.Fatalf("%v != %v", v, b)
	}

	err = rb.Write(b)
	if err != nil {
		t.Fatal(err)
	}

	err = rb.Write(b)
	if err == nil {
		t.Fatal("buf full, expected an error")
	}

	t.Log(rb)
}
