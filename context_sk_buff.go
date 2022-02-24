package mimic

import (
	"encoding/json"
	"fmt"
)

func unmarshalSKBuff(name string, ctx json.RawMessage) (Context, error) {
	var result LinuxContextSKBuff
	err := json.Unmarshal(ctx, &result)
	if err != nil {
		return nil, err
	}
	result.Name = name

	return &result, nil
}

type LinuxContextSKBuff struct {
	Name string `json:"-"`

	Packet   []byte    `json:"packet"`
	SK       *SK       `json:"sock"`
	Dev      *NetDev   `json:"dev"`
	FlowKeys *FlowKeys `json:"flowKeys"`

	skBuff *SKBuff
}

// GetName return the context name
func (c *LinuxContextSKBuff) GetName() string {
	return c.Name
}

// Load load the context into the memory of the process
func (c *LinuxContextSKBuff) Load(process *Process) error {
	if c.skBuff != nil {
		return fmt.Errorf("context is already loaded, cleanup first before re-loading")
	}

	var err error
	c.skBuff, err = SKBuffFromBytes(c.Packet)
	if err != nil {
		return fmt.Errorf("parse sk_buff: %w", err)
	}

	// If the user specified a custom socket, use that instread
	if c.SK != nil {
		c.skBuff.sk = c.SK
	}

	if c.Dev == nil {
		c.Dev = &NetDev{}
	}
	c.skBuff.dev = c.Dev

	if c.FlowKeys == nil {
		c.FlowKeys = &FlowKeys{}
	}
	c.skBuff.flowKeys = c.FlowKeys

	skBuffentry, err := process.VM.MemoryController.AddEntry(c.skBuff, uint32(c.skBuff.Size()), "sk_buff")
	if err != nil {
		return fmt.Errorf("memory controller add sk_buff: %w", err)
	}

	skEntry, err := process.VM.MemoryController.AddEntry(c.skBuff.sk, uint32(c.skBuff.sk.Size()), "sk")
	if err != nil {
		return fmt.Errorf("memory controller add sk: %w", err)
	}
	c.skBuff.skAddr = skEntry.Addr

	flowKeysEntry, err := process.VM.MemoryController.AddEntry(
		c.skBuff.flowKeys,
		uint32(c.skBuff.flowKeys.Size()),
		"bpf_flow_keys",
	)
	if err != nil {
		return fmt.Errorf("memory controller add flow_keys: %w", err)
	}
	c.skBuff.flowKeysAddr = flowKeysEntry.Addr

	pktEntry, err := process.VM.MemoryController.AddEntry(
		c.skBuff.pkt,
		uint32(len(c.skBuff.pkt.Backing)),
		"sk_buff-pkt",
	)
	if err != nil {
		return fmt.Errorf("memory controller add sk_buff-values: %w", err)
	}

	c.skBuff.head += pktEntry.Addr
	c.skBuff.data += pktEntry.Addr
	c.skBuff.tail += pktEntry.Addr
	c.skBuff.end += pktEntry.Addr
	c.skBuff.computeDataPointers()

	process.Registers.R1 = uint64(skBuffentry.Addr)

	return nil
}

// Cleanup removes the context from the processes memory and makes the context ready to be re-used/re-loaded.
func (c *LinuxContextSKBuff) Cleanup(process *Process) error {
	err := process.VM.MemoryController.DelEntryByObj(c.skBuff)
	if err != nil {
		return fmt.Errorf("mem ctl, del obj: %w", err)
	}

	c.skBuff = nil

	return nil
}
