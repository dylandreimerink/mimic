package mimic

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
)

type LinuxMap interface {
	Init(emulator *LinuxEmulator) error
	GetSpec() ebpf.MapSpec

	// Keys returns a byte slice containing all key values in their byte representation. The side is always a multiple
	// of the about of entries in the map and the key size.
	Keys() []byte

	// Lookup returns a pointer to a value matching the key, or NULL if no matching value can be found.
	// `key` must be the same length as defined in the map spec
	Lookup(key []byte) (uint32, error)
}

type LinuxMapUpdater interface {
	// Updates takes a key, value and flags, key and value slices must match the length of the key and value as defined
	// in the map spec. If successful nil is returned, graceful errors are of type syscall.Errno and can be forwarded
	// to the eBPF VM. Other error types are fatal.
	Update(key []byte, value []byte, flags uint32) error
}

type LinuxMapDeleter interface {
	// Delete takes a key, and removes it from the map
	Delete(key []byte) error
}

func MapSpecToLinuxMap(spec *ebpf.MapSpec) (LinuxMap, error) {
	switch spec.Type {
	case ebpf.Array, ebpf.PerCPUArray, ebpf.ArrayOfMaps:
		// Note: ArrayOfMaps isn't its own type since the normal array type support storage of pointers to maps
		//       the emulator doesn't need to enforce valid values.
		// TODO implement per-CPU array
		return &LinuxArrayMap{
			Spec: spec,
		}, nil

	case ebpf.Hash, ebpf.PerCPUHash, ebpf.HashOfMaps:
		// Note: HashOfMaps isn't its own type since the normal hash map type support storage of pointers to maps
		//       the emulator doesn't need to enforce valid values.
		// TODO implement per-CPU hash map
		return &LinuxHashMap{
			Spec: spec,
		}, nil

	case ebpf.LRUHash, ebpf.LRUCPUHash:
		// TODO implement per-CPU LRU map
		return &LinuxLRUHashMap{
			Spec: spec,
		}, nil

	}

	return nil, fmt.Errorf("unsupported map type '%s'", spec.Type)
}

type LinuxArrayMap struct {
	Spec     *ebpf.MapSpec
	emulator *LinuxEmulator

	backing *PlainMemory
	addr    uint32
}

func (m *LinuxArrayMap) Init(emulator *LinuxEmulator) error {
	size := m.Spec.MaxEntries * m.Spec.ValueSize

	m.emulator = emulator
	m.backing = &PlainMemory{
		Backing: make([]byte, size),
	}
	// TODO set initial KV

	// The the map itself to the memory controller
	_, err := m.emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	// The the value memory to the memory controller
	entry, err := m.emulator.vm.MemoryController.AddEntry(m.backing, size, fmt.Sprintf("%s-values", m.Spec.Name))
	if err != nil {
		return fmt.Errorf("add backing to memory controller: %w", err)
	}
	m.addr = entry.Addr

	return nil
}

func (m *LinuxArrayMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

func (m *LinuxArrayMap) Keys() []byte {
	b := make([]byte, 4*m.Spec.MaxEntries)
	bo := GetNativeEndianness()
	for i := uint32(0); i < m.Spec.MaxEntries; i++ {
		bo.PutUint32(b[i*4:(i+1)*4], i)
	}
	return b
}

func (m *LinuxArrayMap) Lookup(key []byte) (uint32, error) {
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

func (m *LinuxArrayMap) Update(key []byte, value []byte, flags uint32) error {
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

type LinuxHashMap struct {
	Spec     *ebpf.MapSpec
	emulator *LinuxEmulator

	// Go can't use slices as map values, so what we do is we sha256 hash the slice which always results in a
	// uniform sized array which we can use as key. Since we now don't index by the actual key, we also need to
	// store the actual key value so we can return k/v pairs
	mu         sync.RWMutex
	KeyToIndex map[[sha256.Size]byte]int

	// A buffered channel of "free" indexes within the keys and values array.
	freelist chan int

	// We store the original keys, so we can loop over them, the index of a key in `keys` is equal to the index of
	// its value in `values`.
	keys       *PlainMemory
	keysAddr   uint32
	values     *PlainMemory
	valuesAddr uint32
}

func (m *LinuxHashMap) Init(emulator *LinuxEmulator) error {
	if m.keys != nil || m.values != nil {
		return fmt.Errorf("map is still loaded, please cleanup before re-loading")
	}

	// TODO handle no-pre-allocate flag

	m.keys = &PlainMemory{
		Backing:   make([]byte, m.Spec.MaxEntries*m.Spec.KeySize),
		ByteOrder: GetNativeEndianness(),
	}

	m.values = &PlainMemory{
		Backing:   make([]byte, m.Spec.MaxEntries*m.Spec.ValueSize),
		ByteOrder: GetNativeEndianness(),
	}

	m.KeyToIndex = make(map[[sha256.Size]byte]int)
	m.freelist = make(chan int, m.Spec.MaxEntries+1)
	for i := 0; i < int(m.Spec.MaxEntries); i++ {
		m.freelist <- i
	}
	m.emulator = emulator
	// TODO set initial KV

	// The the map itself to the memory controller
	_, err := m.emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	// The the keys memory to the memory controller
	keysEntry, err := m.emulator.vm.MemoryController.AddEntry(
		m.keys,
		uint32(len(m.keys.Backing)),
		fmt.Sprintf("%s-keys", m.Spec.Name),
	)
	if err != nil {
		return fmt.Errorf("add map keys to memory controller: %w", err)
	}
	m.keysAddr = keysEntry.Addr

	// The the values memory to the memory controller
	valuesEntry, err := m.emulator.vm.MemoryController.AddEntry(
		m.values,
		uint32(len(m.values.Backing)),
		fmt.Sprintf("%s-values", m.Spec.Name),
	)
	if err != nil {
		return fmt.Errorf("add map values to memory controller: %w", err)
	}
	m.valuesAddr = valuesEntry.Addr

	return nil
}

func (m *LinuxHashMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

func (m *LinuxHashMap) Keys() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ks := int(m.Spec.KeySize)
	keys := make([]byte, len(m.KeyToIndex)*ks)
	i := 0

	// Get every index which contains a key
	for _, idx := range m.KeyToIndex {
		// Read the value of the key at idx into keys at i
		err := m.keys.Read(uint32(idx*ks), keys[i*ks:(i+1)*ks])
		i++
		if err != nil {
			// Can't really do anything, this is to keep linters from getting angry
			continue
		}
	}

	return keys
}

func (m *LinuxHashMap) Lookup(key []byte) (uint32, error) {
	if len(key) != int(m.Spec.KeySize) {
		return 0, fmt.Errorf("size of given key doesn't match key size in map spec")
	}

	keyHash := sha256.Sum256(key)

	// TODO add support for BPF_F_LOCK to avoid race-conditions in BPF land

	// Lock map to avoid race-conditions in go-land
	m.mu.RLock()
	idx, found := m.KeyToIndex[keyHash]
	m.mu.RUnlock()
	if !found {
		// Return NULL if value doesn't exist
		return 0, nil
	}

	valueOffset := uint32(idx) * m.Spec.ValueSize

	return m.valuesAddr + valueOffset, nil
}

func (m *LinuxHashMap) Update(key []byte, value []byte, flags uint32) error {
	if len(key) != int(m.Spec.KeySize) {
		return fmt.Errorf("size of given key doesn't match key size in map spec")
	}
	if len(value) != int(m.Spec.ValueSize) {
		return fmt.Errorf("size of given value doesn't match value size in map spec")
	}

	// TODO add support for BPF_F_LOCK to avoid race-conditions in BPF land

	keyHash := sha256.Sum256(key)

	// Lock map to avoid race-conditions in go-land
	m.mu.RLock()
	idx, found := m.KeyToIndex[keyHash]
	m.mu.RUnlock()
	if !found {
		// If the keys doesn't exist in the map yet, get a free spot from the free list
		select {
		case idx = <-m.freelist:
		default:
			// The map is full if we are out of free indices
			return syscall.E2BIG
		}

		// Lock map to avoid race-conditions in go-land
		m.mu.Lock()
		m.KeyToIndex[keyHash] = idx
		m.mu.Unlock()
	}

	keyOff := uint32(idx) * m.Spec.KeySize
	valueOff := uint32(idx) * m.Spec.ValueSize

	err := m.keys.Write(keyOff, key)
	if err != nil {
		return fmt.Errorf("error while writing to keys memory")
	}

	err = m.values.Write(valueOff, value)
	if err != nil {
		return fmt.Errorf("error while writing to keys memory")
	}

	return nil
}

func (m *LinuxHashMap) Delete(key []byte) error {
	if len(key) != int(m.Spec.KeySize) {
		return fmt.Errorf("size of given key doesn't match key size in map spec")
	}

	keyHash := sha256.Sum256(key)
	// Lock map to avoid race-conditions in go-land
	m.mu.RLock()
	idx, found := m.KeyToIndex[keyHash]
	m.mu.RUnlock()
	if !found {
		// nothing to do
		return nil
	}

	// Delete key from map
	m.mu.Lock()
	delete(m.KeyToIndex, keyHash)
	m.mu.Unlock()

	// Note: Zero-ing out the key and value doesn't seem necessary, what does the actual kernel do?

	// Return idx of k/v pair to the freelist
	select {
	case m.freelist <- idx:
	default:
		panic("freelist is full")
	}

	return nil
}

type LinuxLRUHashMap struct {
	Spec *ebpf.MapSpec
	// wrap an normal hashmap
	hashMap *LinuxHashMap

	mu        sync.Mutex
	usageList *list.List
}

func (m *LinuxLRUHashMap) Init(emulator *LinuxEmulator) error {
	m.hashMap = &LinuxHashMap{
		Spec: m.Spec,
	}
	err := m.hashMap.Init(emulator)
	if err != nil {
		return err
	}

	m.usageList = list.New()

	return nil
}

func (m *LinuxLRUHashMap) GetSpec() ebpf.MapSpec {
	return *m.hashMap.Spec
}

func (m *LinuxLRUHashMap) Keys() []byte {
	return m.hashMap.Keys()
}

func (m *LinuxLRUHashMap) Lookup(key []byte) (uint32, error) {
	valPtr, err := m.hashMap.Lookup(key)
	if valPtr == 0 || err != nil {
		return valPtr, err
	}

	// Lookup success, update LRU
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the key in the list, and move it to the front
	for e := m.usageList.Front(); e != nil; e = e.Next() {
		if lk, ok := e.Value.([]byte); ok && bytes.Equal(lk, key) {
			m.usageList.MoveToFront(e)
			break
		}
	}

	return valPtr, nil
}

func (m *LinuxLRUHashMap) Update(key []byte, value []byte, flags uint32) error {
	err := m.hashMap.Update(key, value, flags)
	if err != nil {
		// If an unknown error, don't do anything
		if err != syscall.E2BIG {
			return err
		}

		// If the hash map is full, we have to evict the last/least recently used value
		back := m.usageList.Back()
		if back == nil || back.Value == nil {
			return fmt.Errorf("map is full by LRU is empty")
		}

		key, ok := back.Value.([]byte)
		if !ok {
			return fmt.Errorf("type other than byte slice in LRU")
		}

		err = m.Delete(key)
		if err != nil {
			return fmt.Errorf("evict error: %w", err)
		}

		err = m.hashMap.Update(key, value, flags)
		if err != nil {
			return fmt.Errorf("second update error: %w", err)
		}
	}

	// Update success, update LRU
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false

	// Find the key in the list, and move it to the front
	for e := m.usageList.Front(); e != nil; e = e.Next() {
		if lk, ok := e.Value.([]byte); ok && bytes.Equal(lk, key) {
			m.usageList.MoveToFront(e)
			found = true
			break
		}
	}

	// If the key doesn't exist in the LRU yet, add it at the top.
	if !found {
		m.usageList.PushFront(key)
	}

	return nil
}

func (m *LinuxLRUHashMap) Delete(key []byte) error {
	err := m.hashMap.Delete(key)
	if err != nil {
		return err
	}

	// Delete success, update LRU
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the key in the list, and remove it
	for e := m.usageList.Front(); e != nil; e = e.Next() {
		if lk, ok := e.Value.([]byte); ok && bytes.Equal(lk, key) {
			m.usageList.Remove(e)
			break
		}
	}

	return nil
}
