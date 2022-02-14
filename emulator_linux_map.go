package mimic

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// LinuxMap is an interface which describes the common functions each map for the LinuxEmulator has. LinuxMaps are
// initialized by the LinuxEmulator upon being added to the emulator and are expected to be ready to store data after
// that. Every map type is expected to be able to return a list of valid keys and for these keys to be retrieved via
// Lookup, this is so the Host can always inspect the map contents. Other "actions" like modifying the maps are optional
// and have their own interfaces.
type LinuxMap interface {
	Init(emulator *LinuxEmulator) error
	GetSpec() ebpf.MapSpec

	// Keys returns a byte slice containing all key values in their byte representation. The size is always a multiple
	// of the about of entries in the map and the key size.
	Keys() []byte

	// Lookup returns a pointer to a value matching the key, or NULL if no matching value can be found.
	// `key` must be the same length as defined in the map spec
	Lookup(key []byte, cpuid int) (uint32, error)
}

// LinuxMapUpdater describes a LinuxMap which can update any value as long as the key is known.
type LinuxMapUpdater interface {
	// Updates takes a key, value and flags, key and value slices must match the length of the key and value as defined
	// in the map spec. If successful nil is returned, graceful errors are of type syscall.Errno and can be forwarded
	// to the eBPF VM. Other error types are fatal.
	Update(key []byte, value []byte, flags uint32, cpuid int) error
}

// LinuxMapDeleter describes a LinuxMap which can delete any value as long as the key is known.
type LinuxMapDeleter interface {
	// Delete takes a key, and removes it from the map
	Delete(key []byte) error
}

// MapSpecToLinuxMap translates a map specification to a LinuxMap type which can be used in the LinuxEmulator.
func MapSpecToLinuxMap(spec *ebpf.MapSpec) (LinuxMap, error) {
	switch spec.Type {
	case ebpf.Array, ebpf.ArrayOfMaps:
		// Note: ArrayOfMaps isn't its own type since the normal array type support storage of pointers to maps
		//       the emulator doesn't need to enforce valid values.
		return &LinuxArrayMap{
			Spec: spec,
		}, nil

	case ebpf.PerCPUArray:
		return &LinuxPerCPUArrayMap{
			Spec: spec,
		}, nil

	case ebpf.ProgramArray:
		return &LinuxProgArrayMap{
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
