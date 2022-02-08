package mimic

import (
	"encoding/json"
	"fmt"
	"io"
)

// Context describes a object which provides all information needed to emulate a specific eBPF environment. A
// context contains both the initial arguments(R1-R5) of a eBPF program as well as data which can be used by the
// emulator in helper functions.
type Context interface {
	GetName() string
	// Load is called when a new process is started, the context is expected to construct a memory object to be passed
	// to the program, register it in the memory controller and set initial argument registers(R1-R5)
	Load(process *Process) error
	// Cleanup is called when a process exists, the Context is expected to delete all its memory from the memory
	// controller.
	Cleanup(process *Process) error
}

// ContextUnmarshaller unmarshals JSON into a specific context
type ContextUnmarshaller func(name string, ctx json.RawMessage) (Context, error)

var contextUnmarshallers = make(map[string]ContextUnmarshaller)

// RegisterContextUnmarshaller is used to register custom context type unmarshallers which will be invoked by
// UnmarshalContextJSON if any context is passed in with "type" set to `ctxType`.
func RegisterContextUnmarshaller(ctxType string, fn ContextUnmarshaller) {
	if _, found := contextUnmarshallers[ctxType]; found {
		return
	}

	contextUnmarshallers[ctxType] = fn
}

func init() {
	RegisterContextUnmarshaller("generic", unmarshalGeneric)
	RegisterContextUnmarshaller("xdp_md", unmarshalXDPmd)
}

type protoCtx struct {
	Name string          `json:"name"`
	Type string          `json:"type"`
	Ctx  json.RawMessage `json:"ctx"`
}

// UnmarshalContextJSON attempts to unmarshal json into a Context. This function expects the top level element to be a
// object with "name" and "type" string fields where "type" is a unique name of the context type. The "ctx" field should
// contain the context type specific object.
//
// Custom context types can also be decoded, additional unmarshallers can be added with the RegisterContextUnmarshaller
// function.
func UnmarshalContextJSON(r io.Reader) (Context, error) {
	var ctx protoCtx
	d := json.NewDecoder(r)
	err := d.Decode(&ctx)
	if err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	unmarshalFn := contextUnmarshallers[ctx.Type]
	if unmarshalFn == nil {
		return nil, fmt.Errorf("no context unmarshaller registered for type '%s'", ctx.Type)
	}

	return unmarshalFn(ctx.Name, ctx.Ctx)
}
