package mimic

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

var _ VMMem = (*PlainMemory)(nil)

// PlainMemory is the simplest implementation of VMMem possible, it is just a []byte with no additional information
// about its contents. The ByteOrder is used when Load'in or Store'ing scalar values. If ByteOrder is not set
// the native endianness will be used.
type PlainMemory struct {
	Backing   []byte
	ByteOrder binary.ByteOrder
}

// TODO it is fairly common to reuse plain memories of the same size, the process stack for example. This would be a
// good candidate for a freelist/memory pool since they can be large. In the case of plain memory we would have to
// group them by size.

// Load loads a scalar value of the given `size` and `offset` from the memory.
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

// Store stores a scalar value of the given `size` and `offset` from the memory.
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
