package mimic

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
)

var (
	_ LinuxMap       = (*LinuxQueueMap)(nil)
	_ LinuxMapPopper = (*LinuxQueueMap)(nil)
	_ LinuxMapPusher = (*LinuxQueueMap)(nil)
)

// LinuxQueueMap is the emulated version of ebpf.Queue / BPF_MAP_TYPE_QUEUE.
// This map type has no keys, value sizes are fixed, but is configurable. This map type is a FIFO queue.
type LinuxQueueMap struct {
	Spec *ebpf.MapSpec

	emulator *LinuxEmulator
	buffer   *ringBuffer
}

// Init initializes the map, part of the LinuxMap implementation
func (m *LinuxQueueMap) Init(emulator *LinuxEmulator) error {
	size := (1 + m.Spec.MaxEntries) * m.Spec.ValueSize

	m.emulator = emulator

	m.buffer = &ringBuffer{}
	err := m.buffer.Init(&emulator.vm.MemoryController, int(size), fmt.Sprintf("%s-values", m.Spec.Name))
	if err != nil {
		return fmt.Errorf("buf init: %w", err)
	}

	// The the map itself to the memory controller
	_, err = emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	return nil
}

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxQueueMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

// Indices returns the amount of per-cpu indexes.
func (m *LinuxQueueMap) Indices() int {
	return 1
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
func (m *LinuxQueueMap) Keys(cpuid int) []byte {
	values := m.buffer.used() / m.Spec.ValueSize
	b := make([]byte, 4*values)
	bo := GetNativeEndianness()
	for i := uint32(0); i < values; i++ {
		bo.PutUint32(b[i*4:(i+1)*4], i)
	}
	return b
}

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
func (m *LinuxQueueMap) Lookup(key []byte, cpuid int) (uint32, error) {
	// Map is empty
	if m.buffer.Used() < m.Spec.ValueSize {
		return 0, nil
	}

	index := GetNativeEndianness().Uint32(key)
	return m.buffer.PeekAddr(m.Spec.ValueSize * index)
}

// Push pushes a new value into the ring buffer
func (m *LinuxQueueMap) Push(value []byte, cpuid int) error {
	if len(value) != int(m.Spec.ValueSize) {
		return fmt.Errorf("value doesn't match the value size of the map")
	}

	return m.buffer.Write(value)
}

// Pop pops a value from the ring buffer
func (m *LinuxQueueMap) Pop(cpuid int) (uint32, error) {
	addr, err := m.buffer.ReadAddr(m.Spec.ValueSize)
	if err != nil {
		return 0, fmt.Errorf("buf read value: %w", err)
	}

	return addr, nil
}

var (
	_ LinuxMap       = (*LinuxStackMap)(nil)
	_ LinuxMapPopper = (*LinuxStackMap)(nil)
	_ LinuxMapPusher = (*LinuxStackMap)(nil)
)

// LinuxStackMap is the emulated version of ebpf.PerfEventArray / BPF_MAP_TYPE_PERF_EVENT_ARRAY.
// Array maps have 4 byte integer keys from 0 to Spec.MaxEntries with arbitrary values
type LinuxStackMap struct {
	Spec *ebpf.MapSpec

	emulator *LinuxEmulator

	mu     sync.Mutex
	stack  *PlainMemory
	topOff uint32
	addr   uint32
}

// Init initializes the map, part of the LinuxMap implementation
func (m *LinuxStackMap) Init(emulator *LinuxEmulator) error {
	m.emulator = emulator

	size := m.Spec.MaxEntries * m.Spec.ValueSize
	m.stack = &PlainMemory{
		Backing: make([]byte, size),
	}
	m.topOff = size

	entry, err := emulator.vm.MemoryController.AddEntry(m.stack, size, fmt.Sprintf("%s-values", m.Spec.Name))
	if err != nil {
		return fmt.Errorf("add map values to memory controller: %w", err)
	}
	m.addr = entry.Addr

	// The the map itself to the memory controller
	_, err = emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	return nil
}

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxStackMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

// Indices returns the amount of per-cpu indexes.
func (m *LinuxStackMap) Indices() int {
	return 1
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
func (m *LinuxStackMap) Keys(cpuid int) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	values := (uint32(len(m.stack.Backing)) - m.topOff) / m.Spec.ValueSize
	fmt.Println(values)
	b := make([]byte, 4*values)
	bo := GetNativeEndianness()
	for i := uint32(0); i < values; i++ {
		bo.PutUint32(b[i*4:(i+1)*4], i)
	}
	return b
}

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
func (m *LinuxStackMap) Lookup(key []byte, cpuid int) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Map is empty
	if int(m.topOff) == len(m.stack.Backing) {
		return 0, nil
	}

	index := GetNativeEndianness().Uint32(key)
	return m.addr + m.topOff + (m.Spec.ValueSize * index), nil
}

// Push pushes a new value into the ring buffer
func (m *LinuxStackMap) Push(value []byte, cpuid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(value) != int(m.Spec.ValueSize) {
		return fmt.Errorf("value doesn't match the value size of the map")
	}

	// If stack is full
	if int(m.topOff)-int(m.Spec.ValueSize) < 0 {
		return syscall.E2BIG
	}

	m.topOff -= m.Spec.ValueSize

	return m.stack.Write(m.topOff, value)
}

// Pop pops a value from the ring buffer
func (m *LinuxStackMap) Pop(cpuid int) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Map is empty
	if int(m.topOff)+int(m.Spec.ValueSize) > len(m.stack.Backing) {
		return 0, nil
	}

	off := m.topOff
	m.topOff += m.Spec.ValueSize

	return m.addr + off, nil
}
