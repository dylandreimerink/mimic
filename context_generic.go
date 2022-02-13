package mimic

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

func unmarshalGeneric(name string, ctx json.RawMessage) (Context, error) {
	var result GenericContext
	err := json.Unmarshal(ctx, &result)
	if err != nil {
		return nil, err
	}
	result.Name = name

	return &result, nil
}

// GenericContextRegisters are registers which the generic context can set when loading
type GenericContextRegisters struct {
	R1 string `json:"r1,omitempty"`
	R2 string `json:"r2,omitempty"`
	R3 string `json:"r3,omitempty"`
	R4 string `json:"r4,omitempty"`
	R5 string `json:"r5,omitempty"`
}

// GenericContext implements mimic.Context. The goal of GenericContext and its GenericContext... struct types is to
// provide a method to construct any type of eBPF context. Being generic also means we have to be very verbose which
// is not always desirable, it is recommended to use specific contexts whenever possible, but this type can always be
// used as a fallback in situations where no specific context type exists.
type GenericContext struct {
	Name      string                  `json:"-"`
	Registers GenericContextRegisters `json:"registers"`
	Memory    []GenericContextMemory  `json:"memory"`
	Emulator  map[string]interface{}  `json:"emulator"`

	loaded bool
}

// MarshalJSON implements json.Marshaler
func (c *GenericContext) MarshalJSON() ([]byte, error) {
	type Alias GenericContext
	a := Alias(*c)
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	proto := protoCtx{
		Name: c.Name,
		Type: "generic",
		Ctx:  b,
	}

	return json.Marshal(proto)
}

// GetName returns the name of the context
func (c *GenericContext) GetName() string {
	return c.Name
}

// Load loads the context into a process. Load is called by the VM when creating a new process, users don't have to
// call this function manually. Loading a context into a process will register memory for the context at the memory
// controller of the VM.
func (c *GenericContext) Load(process *Process) error {
	if c.loaded {
		return fmt.Errorf("context is already loaded, please cleanup before re-loading")
	}

	regVal := func(memName string) (uint64, error) {
		var mem *GenericContextMemory
		for i, m := range c.Memory {
			if m.Name == memName {
				mem = &c.Memory[i]
				break
			}
		}
		if mem == nil {
			return 0, fmt.Errorf("register refers to memory '%s' which doesn't exist", memName)
		}

		switch mem.Type {
		case "block":
			addr, err := mem.Block.GetAddr(process, mem)
			if err != nil {
				return 0, fmt.Errorf("block getaddr: %w", err)
			}

			return uint64(addr), nil
		case "ptr":
			addr, err := mem.Pointer.GetValue(process, c)
			if err != nil {
				return 0, fmt.Errorf("pointer getaddr: %w", err)
			}

			return uint64(addr), nil

		case "int":
			return uint64(mem.Int.Value), nil

		case "struct":
			addr, err := mem.Struct.GetAddr(process, c, mem)
			if err != nil {
				return 0, fmt.Errorf("struct getaddr: %w", err)
			}

			return uint64(addr), nil
		}

		return 0, fmt.Errorf("unknown memory type '%s'", mem.Type)
	}

	if c.Registers.R1 != "" {
		val, err := regVal(c.Registers.R1)
		if err != nil {
			return fmt.Errorf("r1: %w", err)
		}
		process.Registers.R1 = val
	}

	if c.Registers.R2 != "" {
		val, err := regVal(c.Registers.R2)
		if err != nil {
			return fmt.Errorf("r2: %w", err)
		}
		process.Registers.R2 = val
	}

	if c.Registers.R3 != "" {
		val, err := regVal(c.Registers.R3)
		if err != nil {
			return fmt.Errorf("r3: %w", err)
		}
		process.Registers.R3 = val
	}

	if c.Registers.R4 != "" {
		val, err := regVal(c.Registers.R4)
		if err != nil {
			return fmt.Errorf("r4: %w", err)
		}
		process.Registers.R4 = val
	}

	if c.Registers.R5 != "" {
		val, err := regVal(c.Registers.R5)
		if err != nil {
			return fmt.Errorf("r5: %w", err)
		}
		process.Registers.R5 = val
	}

	return nil
}

// Cleanup cleans up the context, the process call this function the Process.Cleanup is called, users should not have to
// manually call this function. Cleaning up the context will remove the associated memory from the processes memory
// controller and make the context ready to be re-used/re-loaded.
func (c *GenericContext) Cleanup(process *Process) error {
	c.loaded = false

	for _, mem := range c.Memory {
		switch mem.Type {
		case "block":
			err := mem.Block.Cleanup(process)
			if err != nil {
				return err
			}

		case "struct":
			err := mem.Struct.Cleanup(process)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// GenericContextMemory represents a named memory object in the generic context, which can be one of multiple actual
// different memory types. The name for each type within a generic context should be unique.
type GenericContextMemory struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	RawValue json.RawMessage `json:"value"`

	Block   *GenericContextMemoryBlock `json:"-"`
	Pointer *GenericContextPointer     `json:"-"`
	Struct  *GenericContextStruct      `json:"-"`
	Int     *GenericContextInt         `json:"-"`
}

// MarshalJSON implements json.Marshaler
func (m *GenericContextMemory) MarshalJSON() ([]byte, error) {
	if m.Block != nil {
		m.Type = "block"
		b, err := json.Marshal(m.Block)
		if err != nil {
			return nil, err
		}
		m.RawValue = b
	}

	if m.Pointer != nil {
		m.Type = "ptr"
		b, err := json.Marshal(m.Pointer)
		if err != nil {
			return nil, err
		}
		m.RawValue = b
	}

	if m.Struct != nil {
		m.Type = "struct"
		b, err := json.Marshal(m.Struct)
		if err != nil {
			return nil, err
		}
		m.RawValue = b
	}

	if m.Int != nil {
		m.Type = "int"
		b, err := json.Marshal(m.Int)
		if err != nil {
			return nil, err
		}
		m.RawValue = b
	}

	type Alias GenericContextMemory
	a := Alias(*m)
	return json.Marshal(a)
}

// UnmarshalJSON implements json.Unmarshaler
func (m *GenericContextMemory) UnmarshalJSON(b []byte) error {
	// Creating an alias of the current type makes it so that we can call json.Unmarshal on Alias without
	// causing a UnmarshalJSON->UnmarshalJSON infinite look
	type Alias GenericContextMemory
	var a Alias
	err := json.Unmarshal(b, &a)
	if err != nil {
		return err
	}

	*m = GenericContextMemory(a)
	switch m.Type {
	case "block":
		m.Block = &GenericContextMemoryBlock{}
		err = json.Unmarshal(m.RawValue, m.Block)

	case "ptr":
		m.Pointer = &GenericContextPointer{}
		err = json.Unmarshal(m.RawValue, m.Pointer)

	case "struct":
		m.Struct = &GenericContextStruct{}
		err = json.Unmarshal(m.RawValue, m.Struct)

	case "int":
		m.Int = &GenericContextInt{}
		err = json.Unmarshal(m.RawValue, m.Int)

	default:
		return fmt.Errorf("'%s' is not a valid context memory type", m.Type)
	}

	// Delete raw value to make object dumps more clear
	m.RawValue = nil

	return err
}

// GenericContextMemoryBlock is a block of memory, the `Value` will be loaded into the memory controller as a
// PlainMemory object.
type GenericContextMemoryBlock struct {
	Value     []byte
	ByteOrder binary.ByteOrder

	// Address where the struct is loaded in virtual memory
	addr uint32
}

// pseudoGenericContextMemoryBlock is a copy of GenericContextMemoryBlock but with string fields which is used while
// marshaling/unmarshalling json.
type pseudoGenericContextMemoryBlock struct {
	Value     string `json:"value"`
	ByteOrder string `json:"byteorder"`
}

// MarshalJSON implements json.Marshaler
func (m *GenericContextMemoryBlock) MarshalJSON() ([]byte, error) {
	if m.ByteOrder == nil {
		m.ByteOrder = GetNativeEndianness()
	}

	pseudo := pseudoGenericContextMemoryBlock{
		Value:     base64.StdEncoding.EncodeToString(m.Value),
		ByteOrder: m.ByteOrder.String(),
	}

	return json.Marshal(pseudo)
}

// UnmarshalJSON implements json.Unmarshaler
func (m *GenericContextMemoryBlock) UnmarshalJSON(b []byte) error {
	var pseudo pseudoGenericContextMemoryBlock
	err := json.Unmarshal(b, &pseudo)
	if err != nil {
		return err
	}

	m.Value, err = base64.StdEncoding.DecodeString(pseudo.Value)
	if err != nil {
		return err
	}

	switch strings.ToLower(pseudo.ByteOrder) {
	case "le", "littleendian", "little-endian":
		m.ByteOrder = binary.LittleEndian
	case "be", "bigendian", "big-endian":
		m.ByteOrder = binary.BigEndian
	default:
		return fmt.Errorf("'%s' is not a valid byte order", pseudo.ByteOrder)
	}

	return nil
}

// GetAddr returns the virtual address of block of memory within the process. If the block is not yet loaded, calling
// this function will cause the load. If the block was already loaded, the existing memory address is returned.
func (m *GenericContextMemoryBlock) GetAddr(p *Process, g *GenericContextMemory) (uint32, error) {
	if m.addr != 0 {
		return m.addr, nil
	}

	if m.ByteOrder == nil {
		m.ByteOrder = GetNativeEndianness()
	}

	mem := PlainMemory{
		Backing:   make([]byte, len(m.Value)),
		ByteOrder: m.ByteOrder,
	}
	copy(mem.Backing, m.Value)

	entry, err := p.VM.MemoryController.AddEntry(&mem, uint32(len(m.Value)), g.Name)
	if err != nil {
		return 0, err
	}
	m.addr = entry.Addr

	return m.addr, nil
}

// Cleanup will remove the memory block from the memory controller of the given process.
func (m *GenericContextMemoryBlock) Cleanup(p *Process) error {
	if m.addr == 0 {
		return nil
	}

	err := p.VM.MemoryController.DelEntryByAddr(m.addr)
	if err != nil {
		return err
	}

	m.addr = 0

	return nil
}

// GenericContextPointer is a pointer to other memory defined in GenericContext.Memory. Offset is the offset from the
// start of the memory block in bytes and Size is the size of the pointer in bits(32 or 64).
// Pointers can only point to "block" and "struct" memory objects.
type GenericContextPointer struct {
	Memory string `json:"memory"`
	Offset int    `json:"offset"`
	Size   int    `json:"size"`
}

// GetValue returns the value of the pointer(the address of the memory we point to plus the allocation)
func (ptr *GenericContextPointer) GetValue(p *Process, g *GenericContext) (uint32, error) {
	var mem *GenericContextMemory
	for i, m := range g.Memory {
		if m.Name == ptr.Memory {
			mem = &g.Memory[i]
			break
		}
	}
	if mem == nil {
		return 0, fmt.Errorf("pointer refers to memory '%s' which doesn't exist", ptr.Memory)
	}

	switch mem.Type {
	case "struct":
		addr, err := mem.Struct.GetAddr(p, g, mem)
		if err != nil {
			return 0, err
		}

		return addr + uint32(ptr.Offset), nil
	case "block":
		addr, err := mem.Block.GetAddr(p, mem)
		if err != nil {
			return 0, err
		}

		return addr + uint32(ptr.Offset), nil
	default:
		return 0, fmt.Errorf("can't create pointer to memory of type '%s'", mem.Type)
	}
}

// GenericContextStruct is a memory object which describes a memory structure which can be translated into a PlainMemory
// object and loaded into the memory controller of a process.
type GenericContextStruct struct {
	Fields []GenericContextStructField

	// Address where the struct is loaded in virtual memory
	addr uint32
}

// MarshalJSON implements json.Marshaler
func (s *GenericContextStruct) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Fields)
}

// UnmarshalJSON implements json.Unmarshaler
func (s *GenericContextStruct) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.Fields)
}

// GetAddr returns the virtual address of the structure. The call to this function will cause the struct to be
// registered with the memory controller of the process, subsequent calls will return the same address.
func (s *GenericContextStruct) GetAddr(p *Process, g *GenericContext, m *GenericContextMemory) (uint32, error) {
	if s.addr != 0 {
		return s.addr, nil
	}

	var blob []byte
	for i, field := range s.Fields {
		var mem *GenericContextMemory
		for j, m := range g.Memory {
			if m.Name == field.Memory {
				mem = &g.Memory[j]
				break
			}
		}

		if mem == nil {
			return 0, fmt.Errorf("field '%s'(%d) refers to memory '%s' which doesn't exist",
				field.Name,
				i,
				field.Memory,
			)
		}

		switch mem.Type {
		case "block", "struct":
			// TODO including structs in structs isn't uncommon, if we can get the []byte instread of just the addr
			// we can just add all bytes to the blob of this struct.

			// Note: not planning on allowing blocks directly. That is because of the edge-case: what if we include a
			// block in a struct and make a pointer to it? You would have to a: allocate both separately(might be
			// confusing if that was not the users intent), b: have the pointer point to the block inside of the
			// struct(now we have ordering issues, how does the pointer know the block is also referenced by a struct?
			// ). A way to sidestep the issue is to declare 2 types, "block" for pointers and "array" for embeding.
			// We just need to implement "array" TODO...
			return 0, fmt.Errorf(
				"field '%s'(%d) refers to memory of type '%s', which is not supported, only pointers and ints "+
					"can be included in structs",
				field.Name,
				i,
				mem.Type,
			)

		case "ptr":
			val, err := mem.Pointer.GetValue(p, g)
			if err != nil {
				return 0, fmt.Errorf("pointer field '%s'(%d) returned error: %w", field.Name, i, err)
			}

			b := make([]byte, 4)
			GetNativeEndianness().PutUint32(b, val)
			blob = append(blob, b...)

		case "int":
			val, err := mem.Int.GetValue()
			if err != nil {
				return 0, fmt.Errorf("int field '%s'(%d) returned error: %w", field.Name, i, err)
			}
			blob = append(blob, val...)
		}
	}

	mem := PlainMemory{
		Backing:   blob,
		ByteOrder: GetNativeEndianness(),
	}

	entry, err := p.VM.MemoryController.AddEntry(&mem, uint32(len(blob)), m.Name)
	if err != nil {
		return 0, fmt.Errorf("mem ctl, add entry: %w", err)
	}

	s.addr = entry.Addr

	return s.addr, nil
}

// Cleanup removes the structure from the processes memory controller
func (s *GenericContextStruct) Cleanup(p *Process) error {
	if s.addr == 0 {
		return nil
	}

	err := p.VM.MemoryController.DelEntryByAddr(s.addr)
	if err != nil {
		return err
	}

	s.addr = 0

	return nil
}

// GenericContextStructField describes a field of GenericContextStruct
type GenericContextStructField struct {
	Name   string `json:"name"`
	Memory string `json:"memory"`
}

// GenericContextInt is a memory object describing a interger value of a specific bit size(8, 16, 32, or 64).
type GenericContextInt struct {
	Value int64 `json:"value"`
	Size  int   `json:"size"`
}

// GetValue returns the bytes for the given integer in the native byte order.
func (i *GenericContextInt) GetValue() ([]byte, error) {
	switch i.Size {
	case 8:
		return []byte{byte(i.Value)}, nil
	case 16:
		b := make([]byte, 2)
		nativeEndian.PutUint16(b, uint16(i.Value))
		return b, nil

	case 32:
		b := make([]byte, 4)
		nativeEndian.PutUint32(b, uint32(i.Value))
		return b, nil

	case 64:
		b := make([]byte, 8)
		nativeEndian.PutUint64(b, uint64(i.Value))
		return b, nil

	default:
		return nil, fmt.Errorf("'%d' is an invalid int size", i.Size)
	}
}
