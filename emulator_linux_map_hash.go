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

// LinuxHashMap is the emulated version of ebpf.Hash / BPF_MAP_TYPE_HASH.
// Hash maps have arbitrary keys and values.
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

// Init initializes the map, part of the LinuxMap implementation
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

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxHashMap) GetSpec() ebpf.MapSpec {
	return *m.Spec
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
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

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
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

// Update updates an existing value in the map, or add a new value if it didn't exist before.
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

// Delete deletes a values from the map
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

// LinuxLRUHashMap is the emulated version of ebpf.LRUHash / BPF_MAP_TYPE_LRU_HASH.
// This map type is a normal hash map which also records which map values are the Least Recently Used. If the map is
// full and a new value is added, this map type will discard the Least Recently Used value from the map to make room
// for the new value instread of returning a "out of memory" error.
type LinuxLRUHashMap struct {
	Spec *ebpf.MapSpec
	// wrap an normal hashmap
	hashMap *LinuxHashMap

	mu        sync.Mutex
	usageList *list.List
}

// Init initializes the map, part of the LinuxMap implementation
func (m *LinuxLRUHashMap) Init(emulator *LinuxEmulator) error {
	m.hashMap = &LinuxHashMap{
		Spec: m.Spec,
	}
	err := m.hashMap.Init(emulator)
	if err != nil {
		return err
	}

	// The the map itself to the memory controller
	_, err = emulator.vm.MemoryController.AddEntry(m, 8, m.Spec.Name)
	if err != nil {
		return fmt.Errorf("add map to memory controller: %w", err)
	}

	m.usageList = list.New()

	return nil
}

// GetSpec returns the specification of the map, part of the LinuxMap implementation
func (m *LinuxLRUHashMap) GetSpec() ebpf.MapSpec {
	return *m.hashMap.Spec
}

// Keys returns a byte slice which contains all keys in the map, keys are packed, the user is expected to calculate
// the proper window into the slice based on the size of m.Spec.KeySize.
func (m *LinuxLRUHashMap) Keys() []byte {
	return m.hashMap.Keys()
}

// Lookup returns the virtual memory offset to the map value or 0 if no value can be found for the given key.
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

// Update updates an existing value in the map, or add a new value if it didn't exist before.
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

		keyVal, ok := back.Value.([]byte)
		if !ok {
			return fmt.Errorf("type other than byte slice in LRU")
		}

		err = m.Delete(keyVal)
		if err != nil {
			return fmt.Errorf("evict error: %w", err)
		}

		err = m.hashMap.Update(keyVal, value, flags)
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

// Delete deletes a key from the map.
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
