package mimic

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

var _ VMMem = (*RingMemory)(nil)

// RingMemory is very similar to PlainMemory, except RingMemory will wrap around to the start when reading or writing
// out of bounds.
type RingMemory struct {
	Backing   []byte
	ByteOrder binary.ByteOrder
}

// Load loads a scalar value of the given `size` and `offset` from the memory.
func (pm *RingMemory) Load(offset uint32, size asm.Size) (uint64, error) {
	if pm.ByteOrder == nil {
		pm.ByteOrder = GetNativeEndianness()
	}

	b := make([]byte, size.Sizeof())
	err := pm.Read(offset, b)
	if err != nil {
		return 0, err
	}

	switch size {
	case asm.Byte:
		return uint64(b[0]), nil
	case asm.Half:
		return uint64(pm.ByteOrder.Uint16(b)), nil
	case asm.Word:
		return uint64(pm.ByteOrder.Uint32(b)), nil
	case asm.DWord:
		return pm.ByteOrder.Uint64(b), nil
	default:
		return 0, fmt.Errorf("unknown size '%v'", size)
	}
}

// Store stores a scalar value of the given `size` and `offset` from the memory.
func (pm *RingMemory) Store(offset uint32, value uint64, size asm.Size) error {
	bytes := size.Sizeof()

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

	return pm.Write(offset, b)
}

// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
func (pm *RingMemory) Read(offset uint32, b []byte) error {
	// Read from offset to the end.
	n := copy(b, pm.Backing[offset:])
	if n == len(b) {
		// If we filled `b` fully, no need to wrap around
		return nil
	}
	// Wrap around to the start, and copy into the rest of b
	copy(b[n:], pm.Backing)

	return nil
}

// Write write a byte slice of arbitrary size to the memory
func (pm *RingMemory) Write(offset uint32, b []byte) error {
	n := copy(pm.Backing[offset:], b)
	if n == len(b) {
		// If all of `b`'s bytes were copied, no need to wrap around
		return nil
	}

	// Wrap around an copy the rest of the bytes
	copy(pm.Backing, b[n:])

	return nil
}
