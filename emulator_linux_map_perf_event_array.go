package mimic

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
)

var (
	_ LinuxMap       = (*LinuxPerfEventArrayMap)(nil)
	_ LinuxMapPopper = (*LinuxPerfEventArrayMap)(nil)
	_ LinuxMapPusher = (*LinuxPerfEventArrayMap)(nil)
)

// LinuxPerfEventArrayMap is the emulated version of ebpf.PerfEventArray / BPF_MAP_TYPE_PERF_EVENT_ARRAY.
// Array maps have 4 byte integer keys from 0 to Spec.MaxEntries with arbitrary values
type LinuxPerfEventArrayMap struct {
	Spec *ebpf.MapSpec

	emulator *LinuxEmulator

	buffers []*ringBuffer
}

// Init initializes the map, part of the LinuxMap implementation
func (m *LinuxPerfEventArrayMap) Init(emulator *LinuxEmulator) error {
	size := emulator.settings.PerfEventBufferSize
	pageSize := os.Getpagesize()

	// Round up to nearest multiple of pagesize
	if size%pageSize != 0 {
		size += size % pageSize
	}

	m.emulator = emulator

	// If no max entries was specified, use the amount of vCPUs
	indices := int(m.Spec.MaxEntries)
	if indices == 0 {
		indices = emulator.vm.settings.VirtualCPUs
	}

	for i := 0; i < indices; i++ {
		mem := &RingMemory{
			Backing: make([]byte, size),
		}

		entry, err := emulator.vm.MemoryController.AddEntry(mem, uint32(size), fmt.Sprintf("%s-%d", m.Spec.Name, i))
		if err != nil {
			return fmt.Errorf("mem ctl: %w", err)
		}

		m.buffers = append(m.buffers, &ringBuffer{
			backing: mem,
			addr:    entry.Addr,
		})
	}

	// The the map itself to the memory controller
	_, err := emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	return nil
}

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxPerfEventArrayMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

// Indices returns the amount of per-cpu indexes.
func (m *LinuxPerfEventArrayMap) Indices() int {
	return int(m.Spec.MaxEntries)
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
func (m *LinuxPerfEventArrayMap) Keys(cpuid int) []byte {
	if cpuid >= len(m.buffers) {
		return nil
	}

	keys := make([]byte, 0)
	bo := GetNativeEndianness()
	buf := m.buffers[cpuid]

	fmt.Println(buf.reader, buf.writer)

	// Since every value in the buffer has variable length, we can't just calculate the desired offset.
	// We have to walk over the ring buffer, checking the entrySize and skipping to the header of the next entry.
	entrySize := make([]byte, 4)
	key := make([]byte, 4)
	off := uint32(0)
	for i := uint32(0); true; i++ {
		// Add the size of the entry (0 initially, so has no effect on first iter)
		off += GetNativeEndianness().Uint32(entrySize)

		n, err := buf.Peek(off, entrySize)
		if err != nil {
			return keys
		}
		if n != 4 {
			return keys
		}

		bo.PutUint32(key, i)
		keys = append(keys, key...)

		// Add the size of the header
		off += 4
	}

	return keys
}

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
func (m *LinuxPerfEventArrayMap) Lookup(key []byte, cpuid int) (uint32, error) {
	if m.Spec.ValueSize != 4 {
		return 0, fmt.Errorf("this map doesn't contain addresses(has a value size != 4 bytes)")
	}

	if cpuid >= len(m.buffers) {
		return 0, fmt.Errorf("cpu id outside of available buffers")
	}

	buf := m.buffers[cpuid]

	// Since every value in the buffer has variable length, we can't just calculate the desired offset.
	// We have to walk over the ring buffer, checking the entrySize and skipping to the header of the next entry.
	entrySize := make([]byte, 4)
	off := uint32(0)
	for keyVal := int(GetNativeEndianness().Uint32(key)); keyVal >= 0; keyVal-- {
		// Add the size of the entry (0 initially, so has no effect on first iter)
		off += GetNativeEndianness().Uint32(entrySize)

		n, err := buf.Peek(off, entrySize)
		if err != nil {
			return 0, fmt.Errorf("buffer peek: %w", err)
		}
		if n != 4 {
			return 0, fmt.Errorf("key outside of buffer")
		}

		// Add the size of the header
		off += 4
	}

	// The loop above has advances off to just after the header of the desired value. Peeking its address will return
	// a address inside the ringbuffer
	return buf.PeekAddr(off)
}

// Push pushes a new value into the perf event buffer
func (m *LinuxPerfEventArrayMap) Push(value []byte, cpuid int) error {
	if cpuid >= len(m.buffers) {
		return fmt.Errorf("cpu id outside of available buffers")
	}

	size := make([]byte, 4)
	GetNativeEndianness().PutUint32(size, uint32(len(value)))

	buf := m.buffers[cpuid]

	return buf.Write(append(size, value...))
}

// Pop pops a value from the perf event buffer
func (m *LinuxPerfEventArrayMap) Pop(cpuid int) ([]byte, error) {
	if cpuid >= len(m.buffers) {
		return nil, fmt.Errorf("cpu id outside of available buffers")
	}

	buf := m.buffers[cpuid]
	size := make([]byte, 4)
	n, err := buf.Read(size)
	if err != nil {
		return nil, fmt.Errorf("buf read size: %w", err)
	}
	if n != 4 {
		return nil, nil
	}

	val := make([]byte, GetNativeEndianness().Uint32(size))
	n, err = buf.Read(val)
	if err != nil {
		return nil, fmt.Errorf("buf read value: %w", err)
	}
	if n != 4 {
		return nil, nil
	}

	return val, nil
}

// ringBuffer is a ring buffer for a single index of the PerfEventArray
type ringBuffer struct {
	mu      sync.Mutex
	writer  uint32
	reader  uint32
	backing *RingMemory
	addr    uint32
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
