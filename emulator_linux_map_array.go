package mimic

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

var (
	_ LinuxMap        = (*LinuxArrayMap)(nil)
	_ LinuxMapUpdater = (*LinuxArrayMap)(nil)
	_ VMMem           = (*LinuxArrayMap)(nil)
)

// LinuxArrayMap is the emulated version of ebpf.Array / BPF_MAP_TYPE_ARRAY.
// Array maps have 4 byte integer keys from 0 to Spec.MaxEntries with arbitrary values
type LinuxArrayMap struct {
	Spec *ebpf.MapSpec

	emulator *LinuxEmulator
	backing  *PlainMemory
	addr     uint32
}

// Init initializes the map, part of the LinuxMap implementation
func (m *LinuxArrayMap) Init(emulator *LinuxEmulator) error {
	size := m.Spec.MaxEntries * m.Spec.ValueSize

	m.emulator = emulator
	m.backing = &PlainMemory{
		Backing: make([]byte, size),
	}

	// TODO set initial KV

	// The the map itself to the memory controller
	_, err := emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	// The the value memory to the memory controller
	entry, err := emulator.vm.MemoryController.AddEntry(m.backing, size, fmt.Sprintf("%s-values", m.Spec.Name))
	if err != nil {
		return fmt.Errorf("add backing to memory controller: %w", err)
	}
	m.addr = entry.Addr

	return nil
}

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxArrayMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

// Indices returns the amount of per-cpu indexes.
func (m *LinuxArrayMap) Indices() int {
	return 1
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
func (m *LinuxArrayMap) Keys(cpuid int) []byte {
	b := make([]byte, 4*m.Spec.MaxEntries)
	bo := GetNativeEndianness()
	for i := uint32(0); i < m.Spec.MaxEntries; i++ {
		bo.PutUint32(b[i*4:(i+1)*4], i)
	}
	return b
}

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
func (m *LinuxArrayMap) Lookup(key []byte, cpuid int) (uint32, error) {
	if len(key) != 4 {
		return 0, fmt.Errorf("invalid key length, must be 4 bytes for array maps")
	}

	// TODO VM map lookup depending on flags (we don't care about userspace)

	keyVal := GetNativeEndianness().Uint32(key)

	// Out of bounds, key doesn't exist, return NULL
	if keyVal >= m.Spec.MaxEntries {
		return 0, nil
	}

	// Return the address to the backing memory plus the correct offset for the key
	return m.addr + (keyVal * m.Spec.ValueSize), nil
}

// Update updates an existing value in the map, or add a new value if it didn't exist before.
func (m *LinuxArrayMap) Update(key []byte, value []byte, flags uint32, cpuid int) error {
	if len(key) != 4 {
		return fmt.Errorf("invalid key length, must be 4 bytes for array maps")
	}
	if len(value) != int(m.Spec.ValueSize) {
		return fmt.Errorf("invalid value length, must be %d bytes", m.Spec.ValueSize)
	}

	keyVal := GetNativeEndianness().Uint32(key)

	// Out of bounds, return an error
	if keyVal >= m.Spec.MaxEntries {
		return syscall.E2BIG
	}

	return m.backing.Write(keyVal*m.Spec.ValueSize, value)
}

// UpdateObject is similar to Update, accept it take a arbitrary go interface{} as value. The virtual address of the
// object will be stored in the map. The map must have a value size of 4 bytes and the object must already be registered
// with the VMs memory controller.
func (m *LinuxArrayMap) UpdateObject(key []byte, value LinuxMap, flags uint32) error {
	if m.Spec.ValueSize != 4 {
		return fmt.Errorf("this map doesn't contain addresses(has a value size != 4 bytes)")
	}

	entry, found := m.emulator.vm.MemoryController.GetEntryByObject(value)
	if !found {
		return fmt.Errorf("the given value is not registered with the memory controller")
	}

	val := make([]byte, 4)
	GetNativeEndianness().PutUint32(val, entry.Addr)

	return m.Update(key, val, flags, 0)
}

// Load reads a single integer value of 1, 2, 4 or 8 bytes at a specific offset
func (m *LinuxArrayMap) Load(offset uint32, size asm.Size) (uint64, error) {
	if _, isDatasec := m.Spec.Value.(*btf.Datasec); !isDatasec {
		return 0, fmt.Errorf("Can't access non-data-section array map directly")
	}

	return m.backing.Load(offset, size)
}

// Store write a single interger value of 1, 2, 4 or 8 bytes to a specific offset
func (m *LinuxArrayMap) Store(offset uint32, value uint64, size asm.Size) error {
	if _, isDatasec := m.Spec.Value.(*btf.Datasec); !isDatasec {
		return fmt.Errorf("Can't access non-data-section array map directly")
	}

	return m.backing.Store(offset, value, size)
}

// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
func (m *LinuxArrayMap) Read(offset uint32, b []byte) error {
	if _, isDatasec := m.Spec.Value.(*btf.Datasec); !isDatasec {
		return fmt.Errorf("Can't access non-data-section array map directly")
	}

	return m.backing.Read(offset, b)
}

// Write write a byte slice of arbitrary size to the memory
func (m *LinuxArrayMap) Write(offset uint32, b []byte) error {
	if _, isDatasec := m.Spec.Value.(*btf.Datasec); !isDatasec {
		return fmt.Errorf("Can't access non-data-section array map directly")
	}

	return m.backing.Write(offset, b)
}

var (
	_ LinuxMap        = (*LinuxPerCPUArrayMap)(nil)
	_ LinuxMapUpdater = (*LinuxPerCPUArrayMap)(nil)
)

// LinuxPerCPUArrayMap is the emulated version of ebpf.PerCPUArray / BPF_MAP_TYPE_PERCPU_ARRAY.
// Array maps have 4 byte integer keys from 0 to Spec.MaxEntries, it value is the address of a map.
type LinuxPerCPUArrayMap struct {
	Spec *ebpf.MapSpec

	emulator  *LinuxEmulator
	arrayMaps []LinuxArrayMap
}

// Init initializes the map, part of the LinuxMap implementation
func (m *LinuxPerCPUArrayMap) Init(emulator *LinuxEmulator) error {
	if len(m.arrayMaps) > 0 {
		return fmt.Errorf("map is already loaded")
	}

	// The the map itself to the memory controller
	_, err := emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	m.emulator = emulator
	for i := 0; i < emulator.vm.settings.VirtualCPUs; i++ {
		// Rename the sub-array-maps so we can see which belongs to which cpu while debugging
		spec := m.Spec.Copy()
		spec.Name = fmt.Sprintf("%s-cpu%d", spec.Name, i)

		arrayMap := LinuxArrayMap{
			Spec: m.Spec,
		}

		err = arrayMap.Init(emulator)
		if err != nil {
			return err
		}

		m.arrayMaps = append(m.arrayMaps, arrayMap)
	}

	return err
}

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxPerCPUArrayMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

// Indices returns the amount of per-cpu indexes.
func (m *LinuxPerCPUArrayMap) Indices() int {
	return len(m.arrayMaps)
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
func (m *LinuxPerCPUArrayMap) Keys(cpuid int) []byte {
	// Every map generates the same keys anyway
	return m.arrayMaps[cpuid].Keys(cpuid)
}

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
func (m *LinuxPerCPUArrayMap) Lookup(key []byte, cpuid int) (uint32, error) {
	if cpuid < 0 || cpuid >= len(m.arrayMaps) {
		return 0, errors.New("invalid cpuid")
	}

	return m.arrayMaps[cpuid].Lookup(key, cpuid)
}

// Update updates an existing value in the map, or add a new value if it didn't exist before.
func (m *LinuxPerCPUArrayMap) Update(key []byte, value []byte, flags uint32, cpuid int) error {
	if cpuid < 0 || cpuid >= len(m.arrayMaps) {
		return errors.New("invalid cpuid")
	}

	return m.arrayMaps[cpuid].Update(key, value, flags, cpuid)
}
