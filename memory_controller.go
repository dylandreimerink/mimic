package mimic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/asm"
)

// MemoryController is used to link virtual addresses(uint64 values) to Go objects.
type MemoryController struct {
	mu sync.RWMutex
	// List of memory entries, sorted by address
	entries []*MemoryEntry
	// Map of entries index by object, to allow for deletion based on object
	objToEntry map[interface{}]*MemoryEntry
}

func (mc *MemoryController) GetAllEntries() []MemoryEntry {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	ls := make([]MemoryEntry, len(mc.entries))
	for i, entry := range mc.entries {
		ls[i] = entry.Copy()
	}

	return ls
}

func (mc *MemoryController) String() string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	var sb strings.Builder
	fmt.Fprintf(&sb, "0x00000000 - 0x%08x - reserved\n", memStart)
	for _, entry := range mc.entries {
		fmt.Fprintf(&sb, "0x%08x - 0x%08x - %T\n", entry.Addr, entry.Addr+entry.Size, entry.Object)
	}
	return sb.String()
}

// The memory controller will start allocating addresses starting at memStart, so common scalar values like 0, 1
// can't be interpreted as addresses.
const memStart = 0xFFFF

func (mc *MemoryController) AddEntry(obj interface{}, size uint32, name string) (MemoryEntry, error) {
	// 0. Take write lock on mutex
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// 1. Verify that obj is a pointer
	if reflect.TypeOf(obj).Kind() != reflect.Ptr {
		return MemoryEntry{}, errors.New("'obj' must be a pointer type")
	}

	// 2. Do a naive search for an available spot
	i := 0
	addr := uint32(memStart) + 1
	for j := 0; j < len(mc.entries); j++ {
		cur := mc.entries[j]

		// If there is room before the current entry
		if addr+size < cur.Addr {
			i = j
			break
		}

		addr = cur.Addr + cur.Size + 1

		// If we are checking the last entry, see if we have room at the end
		if j == len(mc.entries)-1 {
			avail := math.MaxUint32 - addr
			if avail < size {
				return MemoryEntry{}, errors.New("out of memory")
			}
			i = j + 1
		}
	}

	// 3. Insert sorted
	// Expand the slice by one
	mc.entries = append(mc.entries, nil)
	// Move the contents of the slice so i is now free
	copy(mc.entries[i+1:], mc.entries[i:])
	// Add entry at the sorted location
	mc.entries[i] = &MemoryEntry{
		Name:   name,
		Addr:   addr,
		Size:   size,
		Object: obj,
	}

	// 4. Add entry to inverse map
	if mc.objToEntry == nil {
		mc.objToEntry = make(map[interface{}]*MemoryEntry)
	}
	mc.objToEntry[obj] = mc.entries[i]

	return *mc.entries[i], nil
}

func (mc *MemoryController) GetEntry(addr uint32) (MemoryEntry, uint32, bool) {
	// 0. Take read lock on mutex
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// 1. Perform binary search for the addr on sorted slice(exact match or witing addr and addr+size)
	i := sort.Search(len(mc.entries), func(i int) bool {
		return mc.entries[i].Addr >= addr
	})

	// If the address matches exactly
	if i < len(mc.entries) && mc.entries[i].Addr == addr {
		// 2. If entry was found, return value copy and true
		return *mc.entries[i], 0, true
	}

	// If there is one element before i
	if i != 0 {
		// If the search addr is within the entry
		prev := mc.entries[i-1]
		if addr >= prev.Addr && addr <= prev.Addr+prev.Size {
			// 2. If entry was found, return value copy and true
			return *prev, addr - prev.Addr, true
		}
	}

	// 3. If no entry was found, return empty struct and false
	return MemoryEntry{}, 0, false
}

func (mc *MemoryController) GetEntryByObject(obj interface{}) (MemoryEntry, bool) {
	// 0. Take read lock on mutex
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// 1. Preform lookup in inverted map index
	entry, found := mc.objToEntry[obj]
	if !found {
		// 2. if not found, return empty entry and false
		return MemoryEntry{}, found
	}

	// 3. if found, return value copy and true
	return *entry, true
}

func (mc *MemoryController) DelEntryByAddr(addr uint32) error {
	// 0. Take write lock on mutex
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// 1. Perform binary search for the addr on sorted slice(exact match or witing addr and addr+size)
	i := sort.Search(len(mc.entries), func(i int) bool {
		return mc.entries[i].Addr >= addr
	})

	// If the address matches exactly
	if i < len(mc.entries) && mc.entries[i].Addr == addr {
		delete(mc.objToEntry, mc.entries[i])
		copy(mc.entries[i:], mc.entries[i+1:])
		mc.entries = mc.entries[:len(mc.entries)-1]
		return nil
	}

	// If there is one element before i
	if i != 0 {
		// If the search addr is within the entry
		prev := mc.entries[i-1]
		if addr >= prev.Addr && addr <= prev.Addr+prev.Size {
			delete(mc.objToEntry, mc.entries[i])
			copy(mc.entries[i:], mc.entries[i+1:])
			mc.entries = mc.entries[:len(mc.entries)-1]
			return nil
		}
	}

	// 3. If no entry was found, nothing to do
	return nil
}

func (mc *MemoryController) DelEntryByObj(obj interface{}) error {
	// 0. Take write lock on mutex
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// 1. Lookup object in inverse map index
	entry, found := mc.objToEntry[obj]
	if !found {
		return nil
	}
	// Always delete from the map if we were able to find it
	delete(mc.objToEntry, obj)

	// 2. Perform binary search for the addr on sorted slice(exact match or witing addr and addr+size)
	i := sort.Search(len(mc.entries), func(i int) bool {
		return mc.entries[i].Addr >= entry.Addr
	})

	// If i is out of bounds or closest match isn't the same entry.
	if i >= len(mc.entries) || entry != mc.entries[i] {
		return nil
	}

	// 3. When entry was found, delete from slice and from map
	// Move all elements after i, 1 index to the left(copying over i)
	copy(mc.entries[i:], mc.entries[i+1:])
	// Shrink slice
	mc.entries = mc.entries[:len(mc.entries)-1]

	return nil
}

type MemoryEntry struct {
	Name   string
	Addr   uint32
	Size   uint32
	Object interface{}
}

func (me MemoryEntry) Copy() MemoryEntry {
	return MemoryEntry{
		Name:   me.Name,
		Addr:   me.Addr,
		Size:   me.Size,
		Object: me.Object,
	}
}

// VMMem is memory which which the VM can access(read and write)
type VMMem interface {
	// Load reads a single integer value of 1, 2, 4 or 8 bytes at a specific offset
	Load(offset uint32, size asm.Size) (uint64, error)
	// Store write a single interger value of 1, 2, 4 or 8 bytes to a specific offset
	Store(offset uint32, value uint64, size asm.Size) error
	// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
	Read(offset uint32, b []byte) error
	// Write write a byte slice of arbitrary size to the memory
	Write(offset uint32, b []byte) error
}

var _ VMMem = (*PlainMemory)(nil)

type PlainMemory struct {
	Backing   []byte
	ByteOrder binary.ByteOrder
}

// TODO it is fairly common to reuse plain memories of the same size, the process stack for example. This would be a
// good candidate for a freelist/memory pool since they can be large. In the case of plain memory we would have to
// group them by size.

func (pm *PlainMemory) Load(offset uint32, size asm.Size) (uint64, error) {
	bytes := size.Sizeof()
	if int(offset)+bytes > len(pm.Backing) {
		return 0, fmt.Errorf(
			"reading %d bytes at offset %d will read out of the memory bounds of %d bytes",
			bytes,
			offset,
			len(pm.Backing),
		)
	}

	if pm.ByteOrder == nil {
		pm.ByteOrder = GetNativeEndianness()
	}

	switch size {
	case asm.Byte:
		return uint64(pm.Backing[offset]), nil
	case asm.Half:
		return uint64(pm.ByteOrder.Uint16(pm.Backing[offset : offset+2])), nil
	case asm.Word:
		return uint64(pm.ByteOrder.Uint32(pm.Backing[offset : offset+4])), nil
	case asm.DWord:
		return pm.ByteOrder.Uint64(pm.Backing[offset : offset+8]), nil
	default:
		return 0, fmt.Errorf("unknown size '%v'", size)
	}
}

func (pm *PlainMemory) Store(offset uint32, value uint64, size asm.Size) error {
	bytes := size.Sizeof()
	if int(offset)+bytes > len(pm.Backing) {
		return fmt.Errorf(
			"writing %d bytes at offset %d will overflow the memory of %d bytes",
			bytes,
			offset,
			len(pm.Backing),
		)
	}

	if pm.ByteOrder == nil {
		pm.ByteOrder = GetNativeEndianness()
	}

	b := make([]byte, bytes)
	switch size {
	case asm.Byte:
		b[0] = byte(value)
	case asm.Half:
		pm.ByteOrder.PutUint16(b, uint16(value))
	case asm.Word:
		pm.ByteOrder.PutUint32(b, uint32(value))
	case asm.DWord:
		pm.ByteOrder.PutUint64(b, value)
	default:
		return fmt.Errorf("unknown size '%v'", size)
	}

	copy(pm.Backing[offset:], b)

	return nil
}

// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
func (pm *PlainMemory) Read(offset uint32, b []byte) error {
	if int(offset)+len(b) > len(pm.Backing) {
		return fmt.Errorf(
			"reading %d bytes at offset %d will read out of the memory bounds of %d bytes",
			len(b),
			offset,
			len(pm.Backing),
		)
	}

	copy(b, pm.Backing[offset:])

	return nil
}

// Write write a byte slice of arbitrary size to the memory
func (pm *PlainMemory) Write(offset uint32, b []byte) error {
	if int(offset)+len(b) > len(pm.Backing) {
		return fmt.Errorf(
			"writing %d bytes at offset %d will overflow the memory of %d bytes",
			len(b),
			offset,
			len(pm.Backing),
		)
	}

	copy(pm.Backing[offset:], b)

	return nil
}

var nativeEndian binary.ByteOrder

func GetNativeEndianness() binary.ByteOrder {
	if nativeEndian != nil {
		return nativeEndian
	}

	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}

	return nativeEndian
}
