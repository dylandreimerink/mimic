package mimic

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

func unmarshalXDPmd(name string, ctx json.RawMessage) (Context, error) {
	var result LinuxContextXDP
	err := json.Unmarshal(ctx, &result)
	if err != nil {
		return nil, err
	}
	result.Name = name

	return &result, nil
}

// LinuxContextXDP is a specialized context type for XDP programs.
type LinuxContextXDP struct {
	Name string `json:"-"`

	Headroom      int    `json:"headroom"`
	Tailroom      int    `json:"tailroom"`
	Packet        []byte `json:"packet"`
	IngessIfIndex int32  `json:"ingress_ifidx"`
	RxQueueIndex  int32  `json:"rx_queue_idx"`
	EgressIfIndex int32  `json:"egress_ifidx"`

	pkt   *PlainMemory
	xdpMD *PlainMemory
}

// GetName return the context name
func (c *LinuxContextXDP) GetName() string {
	return c.Name
}

// SetName set the name of the context
func (c *LinuxContextXDP) SetName(name string) {
	c.Name = name
}

// Load load the context into the memory of the process
func (c *LinuxContextXDP) Load(process *Process) error {
	if c.pkt != nil || c.xdpMD != nil {
		return fmt.Errorf("context is already loaded, cleanup first before re-loading")
	}

	c.pkt = &PlainMemory{
		Backing:   make([]byte, c.Headroom+len(c.Packet)+c.Tailroom),
		ByteOrder: GetNativeEndianness(),
	}
	c.xdpMD = &PlainMemory{
		Backing:   make([]byte, 6*4),
		ByteOrder: GetNativeEndianness(),
	}

	err := c.pkt.Write(uint32(c.Headroom), c.Packet)
	if err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	entry, err := process.VM.MemoryController.AddEntry(c.pkt, uint32(len(c.pkt.Backing)), "packet")
	if err != nil {
		return fmt.Errorf("memory controller add pkt memory: %w", err)
	}

	// xdp_md.data
	err = c.xdpMD.Store(0, uint64(entry.Addr)+uint64(c.Headroom), asm.Word)
	if err != nil {
		return fmt.Errorf("store xdp_md.data: %w", err)
	}

	// xdp_md.data_end
	err = c.xdpMD.Store(4, uint64(entry.Addr)+uint64(c.Headroom)+uint64(len(c.Packet)), asm.Word)
	if err != nil {
		return fmt.Errorf("store xdp_md.data_end: %w", err)
	}

	// xdp_md.data_meta
	err = c.xdpMD.Store(8, uint64(entry.Addr)+uint64(c.Headroom), asm.Word)
	if err != nil {
		return fmt.Errorf("store xdp_md.data_meta: %w", err)
	}

	// xdp_md.ingress_ifindex
	err = c.xdpMD.Store(12, uint64(c.IngessIfIndex), asm.Word)
	if err != nil {
		return fmt.Errorf("store xdp_md.ingress_ifindex: %w", err)
	}

	// xdp_md.rx_queue_index
	err = c.xdpMD.Store(16, uint64(c.RxQueueIndex), asm.Word)
	if err != nil {
		return fmt.Errorf("store xdp_md.rx_queue_index: %w", err)
	}

	// xdp_md.egress_ifindex
	err = c.xdpMD.Store(20, uint64(c.EgressIfIndex), asm.Word)
	if err != nil {
		return fmt.Errorf("store xdp_md.egress_ifindex: %w", err)
	}

	xdpEntry, err := process.VM.MemoryController.AddEntry(c.xdpMD, 6*4, "xdp_md")
	if err != nil {
		return fmt.Errorf("mem ctl, add entry xdp_md: %w", err)
	}

	process.Registers.R1 = uint64(xdpEntry.Addr)

	return nil
}

// Cleanup removes the context from the processes memory and makes the context ready to be re-used/re-loaded.
func (c *LinuxContextXDP) Cleanup(process *Process) error {
	err := process.VM.MemoryController.DelEntryByObj(c.pkt)
	if err != nil {
		return fmt.Errorf("mem ctl, del obj: %w", err)
	}

	err = process.VM.MemoryController.DelEntryByObj(c.xdpMD)
	if err != nil {
		return fmt.Errorf("mem ctl, del obj: %w", err)
	}

	c.pkt = nil
	c.xdpMD = nil

	return nil
}
