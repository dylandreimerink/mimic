package mimic

import (
	"fmt"
	"sync"
	"syscall"
)

// ringBuffer is a ring buffer for a single index of the PerfEventArray
type ringBuffer struct {
	mu      sync.Mutex
	writer  uint32
	reader  uint32
	backing *RingMemory
	addr    uint32
}

func (rb *ringBuffer) Init(memCtl *MemoryController, size int, name string) error {
	rb.backing = &RingMemory{
		Backing: make([]byte, size),
	}

	entry, err := memCtl.AddEntry(rb.backing, uint32(size), name)
	if err != nil {
		return fmt.Errorf("mem ctl: %w", err)
	}
	rb.addr = entry.Addr

	return nil
}

// Peek peeks into the buffer, copying up to `len(b)` bytes into `b` if available. `off` is added to the reader offset
// to get the actual offset at which we will read. Peek doesn't change the reader offset.
func (rb *ringBuffer) Peek(off uint32, b []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Can't peek beyond the end of the used bytes
	if uint32(len(b))+off > rb.used() {
		return 0, nil
	}

	off += rb.reader
	if off > rb.size() {
		off -= rb.size()
	}

	err := rb.backing.Read(off, b)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// PeekAddr peeks into the buffer, returning the memory address of the offset from the reader pointer
func (rb *ringBuffer) PeekAddr(off uint32) (uint32, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Can't peek beyond the end of the used bytes
	if off > rb.used() {
		return 0, nil
	}

	off += rb.reader
	if off > rb.size() {
		off -= rb.size()
	}

	return rb.addr + off, nil
}

// ReadAddr returns the address plus the offset to the reader, then advances the reader by the given size.
// Acts as a read, but since the memory is not deleted from the ring, it can be accessed, this is not perfectly thread
// safe, but assuming the buffer is of reasonable size, the contents of the ring will be consumed before being reused.
// This is actually how linux does it as well
// https://elixir.bootlin.com/linux/v5.16.10/source/kernel/bpf/queue_stack_maps.c#L99
func (rb *ringBuffer) ReadAddr(size uint32) (uint32, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if size > rb.used() {
		return 0, nil
	}

	off := rb.reader

	rb.reader += size
	if rb.reader > rb.size() {
		rb.reader -= rb.size()
	}

	return rb.addr + off, nil
}

// Read reads `len(b)` amount of bytes from the buffer and copies it into `b` unless the ringbuffer has not enough data
// to fill `b` and will copy any remainder. Read advances reader pointer by the amount of bytes Read.
func (rb *ringBuffer) Read(b []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if uint32(len(b)) > rb.used() {
		// If `b` is larger than the used data in the buffer, shorten b so we never read past the writer offset
		b = b[:rb.used()]
	}

	err := rb.backing.Read(rb.reader, b)
	if err != nil {
		return 0, err
	}

	rb.reader += uint32(len(b))
	if rb.reader > rb.size() {
		rb.reader -= rb.size()
	}

	return len(b), nil
}

// Write writes the contents of b to the ringbuffer if there is room and advances the writer pointer by the written
// amount.
func (rb *ringBuffer) Write(b []byte) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(b) >= int(rb.remaining()) {
		return syscall.E2BIG
	}

	err := rb.backing.Write(rb.writer, b)
	if err != nil {
		return err
	}

	rb.writer += uint32(len(b))
	if rb.writer > rb.size() {
		rb.writer -= rb.size()
	}

	return nil
}

// Used is the total amount of bytes currently in use
func (rb *ringBuffer) Used() uint32 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.used()
}

func (rb *ringBuffer) used() uint32 {
	if rb.writer >= rb.reader {
		return rb.writer - rb.reader
	}

	return rb.size() - (rb.reader - rb.writer)
}

func (rb *ringBuffer) Remaining() uint32 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.remaining()
}

func (rb *ringBuffer) remaining() uint32 {
	return rb.size() - rb.used()
}

func (rb *ringBuffer) Size() uint32 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size()
}

func (rb *ringBuffer) size() uint32 {
	return uint32(len(rb.backing.Backing))
}
