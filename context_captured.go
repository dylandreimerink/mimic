package mimic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/cilium/ebpf/asm"
)

func unmarshalCaptured(name string, ctx json.RawMessage) (Context, error) {
	var cc CapturedContext

	err := json.Unmarshal(ctx, &cc)
	if err != nil {
		return nil, err
	}

	cc.Sub, err = UnmarshalContextJSON(bytes.NewReader(cc.RawSub))
	if err != nil {
		return nil, err
	}

	return &cc, nil
}

// CapturedContext wraps another context and adds captured helper call data to it which the LinuxEmulator can use
// to replay helper calls instead of actually emulating them, or doing both in some cases.
type CapturedContext struct {
	Sub         Context                                `json:"-"`
	RawSub      json.RawMessage                        `json:"subContext"`
	HelperCalls map[string][]CapturedContextHelperCall `json:"helperCalls"`
}

// MarshalJSON implements json.Marshaler
func (cc *CapturedContext) MarshalJSON() ([]byte, error) {
	type Alias CapturedContext
	a := Alias(*cc)

	subBytes, err := json.Marshal(cc.Sub)
	if err != nil {
		return nil, err
	}
	a.RawSub = json.RawMessage(subBytes)

	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	proto := protoCtx{
		Name: cc.Sub.GetName(),
		Type: "captured",
		Ctx:  b,
	}

	return json.Marshal(proto)
}

// GetName returns the name of the context
func (cc *CapturedContext) GetName() string {
	return cc.Sub.GetName()
}

// SetName sets the name of the context
func (cc *CapturedContext) SetName(name string) {
	cc.Sub.SetName(name)
}

// Load loads the sub-context into memory
func (cc *CapturedContext) Load(process *Process) error {
	return cc.Sub.Load(process)
}

// Cleanup cleans up the allocated memory of the sub-context
func (cc *CapturedContext) Cleanup(process *Process) error {
	return cc.Sub.Cleanup(process)
}

// CapturedContextHelperCall describes a single call to a helper function
type CapturedContextHelperCall struct {
	HelperFn asm.BuiltinFunc               `json:"helperFn"`
	Params   []CapturedContextRegisterData `json:"params"`
	Result   []CapturedContextRegisterData `json:"results"`
}

// CapturedContextRegisterData describes the contexts of a register
type CapturedContextRegisterData struct {
	Reg    asm.Register    `json:"reg"`
	Value  json.RawMessage `json:"value"`
	Scalar uint64          `json:"-"`
	Data   []byte          `json:"-"`
}

// UnmarshalJSON implements json.Unmarshaler
func (crd *CapturedContextRegisterData) UnmarshalJSON(data []byte) error {
	type alias CapturedContextRegisterData
	var a alias

	err := json.Unmarshal(data, &a)
	if err != nil {
		return err
	}
	crd.Reg = a.Reg

	if err = json.Unmarshal(a.Value, &crd.Scalar); err != nil {
		var str string
		if err = json.Unmarshal(a.Value, &str); err != nil {
			return err
		}

		crd.Data, err = base64.StdEncoding.DecodeString(str)
		if err != nil {
			return err
		}
	}

	return nil
}

// MarshalJSON implements json.Marshaler
func (crd *CapturedContextRegisterData) MarshalJSON() ([]byte, error) {
	type alias CapturedContextRegisterData
	var a alias

	a.Reg = crd.Reg
	if len(crd.Data) > 0 {
		base64Json, err := json.Marshal(base64.StdEncoding.EncodeToString(crd.Data))
		if err != nil {
			return nil, err
		}

		a.Value = json.RawMessage(base64Json)
	} else {
		intJSON, err := json.Marshal(crd.Scalar)
		if err != nil {
			return nil, err
		}
		a.Value = json.RawMessage(intJSON)
	}

	return json.Marshal(a)
}
