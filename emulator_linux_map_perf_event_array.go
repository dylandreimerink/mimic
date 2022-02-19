package mimic

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

var (
	_ LinuxMap       = (*LinuxPerfEventArrayMap)(nil)
	_ LinuxMapPusher = (*LinuxPerfEventArrayMap)(nil)
)

// LinuxPerfEventArrayMap is the emulated version of ebpf.PerfEventArray / BPF_MAP_TYPE_PERF_EVENT_ARRAY.
// This map type has no keys, the map has no set value size, each element can be of a different size.
type LinuxPerfEventArrayMap struct {
	Spec *ebpf.MapSpec

	emulator *LinuxEmulator
	buffers  []*ringBuffer
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
		var buf ringBuffer
		err := buf.Init(&emulator.vm.MemoryController, size, fmt.Sprintf("%s-%d", m.Spec.Name, i))
		if err != nil {
			return err
		}

		m.buffers = append(m.buffers, &buf)
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
