package mimic

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

var _ VMMem = (*SKBuff)(nil)

// SKBuff is an emulated version of the Linux socket buffer. A datastructure which Linux uses to keep track of packets
// received on a socket. A SKBuff is a metadata wrapper around the actual packet data, usually part of a linked list
// of other SKBuff objects. It contains a lot of pre-processes data which programs and pointers to the different
// network layers of the packet.
// https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/skbuff.h#L731
//
// eBPF programs can't directly access the sk_buff struct, rather the __sk_buff proxy is used.
// https://elixir.bootlin.com/linux/v5.16.10/source/include/uapi/linux/bpf.h#L5315
// This object never actually exists it memory, just defined to provide the correct offset. When programs are loaded
// into the Linux kernel they are re-written to access the actual sk_buff, this provides API stability.
// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8548
//
// This emulated version is not a perfect replica of the sk_buff, just aims to provide features required for eBPF
// emulation. Instread of re-writing the eBPF program, the SKBuff implements the VMMem interface, which internally
// will do the same conversion as the kernel does.
type SKBuff struct {
	// @next, @prev - Ignoring SKBuff linked list implementation until really necessary
	// TODO @sk - Socket we are owned by

	// @tstamp/@skb_mstamp_ns: Time we arrived/left
	tstamp time.Time

	// @cb  Control buffer. Free for use by every layer. Put private vars here
	cb [48]byte

	// @list - Ignoring SKBuff linked list implementation until really necessary

	// @len: Length of actual data
	len uint
	// @queue_mapping: Queue mapping for multiqueue devices
	queueMapping uint16

	// @pkt_type: Packet class
	pktType skBuffPktType

	// @vlan_present: VLAN tag is present
	vlanPresent bool

	// @tc_index: Traffic control index
	tcIndex uint16
	// @priority Packet queueing priority
	priority uint32
	// @skb_iif: ifindex of device we arrived on
	skbIIF int
	// @hash: the packet hash
	hash uint32
	// @vlan_proto: vlan encapsulation protocol
	vlanProto uint16
	// @vlan_tci: vlan tag control information
	vlanTCI uint16
	// @napi_id: id of the NAPI struct this skb came from
	// @sender_cpu: (aka @napi_id) source CPU in XPS
	napiIDOrsenderCPU uint
	// @mark: Generic packet mark
	// @reserved_tailroom: (aka @mark) number of bytes of free space available at the tail of an sk_buff
	markOrReservedTailroom uint32
	// @protocol: Packet protocol from driver
	protocol uint16
	// @transport_header: Transport layer header
	transportHdr uint16
	// @network_header: Network layer header
	networkHdr uint16
	// @mac_header: Link layer header
	macHdr uint16

	sk     *SK
	skAddr uint32

	dev *NetDev

	flowKeys     *FlowKeys
	flowKeysAddr uint32

	// http://vger.kernel.org/~davem/skb_data.html

	// The packet data, is plain memory so when loaded into the VM, it can be used for direct packet access
	pkt *PlainMemory
	// The virtual address of `pkt`
	head uint32
	// The offset within `pkt` where the actual data starts
	data uint32
	// The offset within `pkt` where the actual data stops
	tail uint32
	// The offset within `pkt` where tailroom stops, and the skb_shared_info starts
	end uint32
}

// SKBuffFromBytes parses the packet and constructs a SKBuff from it.
//
// Basically do the same as https://elixir.bootlin.com/linux/v5.16.10/source/net/bpf/test_run.c#L565
func SKBuffFromBytes(pktData []byte) (*SKBuff, error) {
	// TODO technically, Ethernet is not the only link layer, What about UNIX sockets for example?
	pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
	var skBuf SKBuff

	// https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/skbuff.h#L2751
	const headroom = 32
	// The amount of bytes we reserve after the end of the packet
	// Which is max(sizeof(struct skb_shared_info), 64). 64 because that is the value of L1_CACHE_BYTES on x86 CPUs
	const tailroom = 64

	// 1. data = bpf_test_init(kattr, size, NET_SKB_PAD + NET_IP_ALIGN,
	// 		SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	data := &PlainMemory{
		Backing:   make([]byte, headroom+len(pktData)+tailroom),
		ByteOrder: binary.BigEndian,
	}
	copy(data.Backing[headroom:], pktData)

	// 2. sk = sk_alloc(net, AF_UNSPEC, GFP_USER, &bpf_dummy_proto, 1);
	skBuf.sk = &SK{
		Family: unix.AF_UNSPEC,
		srcIP4: make(net.IP, 4),
		dstIP4: make(net.IP, 4),
		srcIP6: make(net.IP, 16),
		dstIP6: make(net.IP, 16),
	}

	// 3. sock_init_data(NULL, sk);
	// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/sock.c#L3201
	skBuf.sk.State = unix.BPF_TCP_CLOSE

	// 4. skb = build_skb(data, 0);
	// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/skbuff.c#L190
	skBuf.pkt = data
	skBuf.head = 0
	skBuf.data = 0

	// skb_reset_tail_pointer(skb);
	skBuf.tail = skBuf.data - skBuf.head
	skBuf.end = skBuf.tail + uint32(len(pktData))

	// 5. skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
	skBuf.head += headroom
	skBuf.data += headroom

	// 6. __skb_put(skb, size);
	skBuf.tail += uint32(len(pktData))
	skBuf.len += uint(len(pktData))

	// TODO 7.
	// if (ctx && ctx->ifindex > 1) {
	//     dev = dev_get_by_index(net, ctx->ifindex);

	offset := headroom

	var (
		linkLayer      gopacket.Layer
		networkLayer   gopacket.Layer
		transportLayer gopacket.Layer
	)

	// https://elixir.bootlin.com/linux/v5.16.10/source/net/ethernet/eth.c#L155

	for _, l := range pkt.Layers() {
		switch l := l.(type) {
		case *layers.Dot1Q:
			skBuf.vlanProto = uint16(l.Type)
			skBuf.vlanTCI = binary.BigEndian.Uint16(l.Contents[:2])
			skBuf.vlanPresent = true

		case *layers.Ethernet:
			if linkLayer != nil {
				// This would be the second ethernet packet, some sort of encapsulation?
				// TODO handle this case
				return nil, fmt.Errorf("handling of multiple link layers not supported")
			}

			linkLayer = l

			// https://elixir.bootlin.com/linux/v5.16.10/source/net/ethernet/eth.c#L162
			// skb_reset_mac_header(skb);
			skBuf.macHdr = uint16(offset)

			// TODO make Go version of
			// 			if (unlikely(!ether_addr_equal_64bits(eth->h_dest,
			// 				dev->dev_addr))) {
			// if (unlikely(is_multicast_ether_addr_64bits(eth->h_dest))) {
			//   if (ether_addr_equal_64bits(eth->h_dest, dev->broadcast))
			// 	  skb->pkt_type = PACKET_BROADCAST;
			//   else
			// 	  skb->pkt_type = PACKET_MULTICAST;
			// } else {
			//   skb->pkt_type = PACKET_OTHERHOST;
			// }
			// }

			// skb->protocol = eth_type_trans(skb, dev);
			skBuf.protocol = uint16(l.EthernetType)

			// TODO support Real 802.2 LLC? https://elixir.bootlin.com/linux/v5.16.10/source/net/ethernet/eth.c#L204

		case *layers.IPv4, *layers.IPv6:
			if networkLayer != nil {
				// This would be the second network layer, some sort of encapsulation?
				// TODO handle this case
				return nil, fmt.Errorf("handling of multiple network layers not supported")
			}

			networkLayer = l

			// skb_reset_network_header(skb);
			skBuf.networkHdr = uint16(offset)

			switch l := l.(type) {
			case *layers.IPv4:
				// https://elixir.bootlin.com/linux/v5.16.10/source/net/bpf/test_run.c#L640
				skBuf.sk.Family = unix.AF_INET
				skBuf.sk.srcIP4 = l.SrcIP
				skBuf.sk.dstIP4 = l.DstIP
			case *layers.IPv6:
				// https://elixir.bootlin.com/linux/v5.16.10/source/net/bpf/test_run.c#L648
				skBuf.sk.Family = unix.AF_INET6
				skBuf.sk.srcIP6 = l.SrcIP
				skBuf.sk.dstIP6 = l.DstIP
			}

		case *layers.TCP, *layers.UDP:
			if transportLayer != nil {
				// This would be the second transport layer, some sort of encapsulation?
				// TODO handle this case
				return nil, fmt.Errorf("handling of multiple transport layers not supported")
			}

			transportLayer = l

			// The prog test doesn't do this, but figured it can't hurt
			switch l := l.(type) {
			case *layers.TCP:
				skBuf.sk.SrcPort = uint32(l.SrcPort)
				skBuf.sk.DstPort = uint32(l.DstPort)
			case *layers.UDP:
				skBuf.sk.SrcPort = uint32(l.SrcPort)
				skBuf.sk.DstPort = uint32(l.DstPort)
			}

			skBuf.transportHdr = uint16(offset)
		}

		offset += len(l.LayerContents())
	}

	// https://elixir.bootlin.com/linux/v5.16.10/source/net/bpf/test_run.c#L662
	// bpf_compute_data_pointers(skb);
	skBuf.computeDataPointers()

	return &skBuf, nil
}

// https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/filter.h#L693
func (sk *SKBuff) computeDataPointers() {
	// https://elixir.bootlin.com/linux/v5.16.10/source/include/net/sch_generic.h#L442
	const qdiscSKBCBLen = 28

	// Just data since metadata len is always zero
	// cb->data_meta = skb->data - skb_metadata_len(skb);
	GetNativeEndianness().PutUint32(sk.cb[qdiscSKBCBLen+0:], sk.data)

	// skb_headlen(skb) is always zero
	// cb->data_end  = skb->data + skb_headlen(skb);
	GetNativeEndianness().PutUint32(sk.cb[qdiscSKBCBLen+4:], sk.data)
}

// Load reads a single integer value of 1, 2, 4 or 8 bytes at a specific offset
func (sk *SKBuff) Load(offset uint32, size asm.Size) (uint64, error) {
	return sk.convertAccess(offset, 0, size, true)
}

// Store write a single interger value of 1, 2, 4 or 8 bytes to a specific offset
func (sk *SKBuff) Store(offset uint32, value uint64, size asm.Size) error {
	_, err := sk.convertAccess(offset, value, size, false)
	return err
}

var errReadOnly = errors.New("this field is read only, can only be modified via helper functions")

// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8548
func (sk *SKBuff) convertAccess(offset uint32, value uint64, size asm.Size, load bool) (uint64, error) {
	toSize := func(i uint64) uint64 {
		switch size {
		case asm.Byte:
			return uint64(uint8(i))
		case asm.Half:
			return uint64(uint16(i))
		case asm.Word:
			return uint64(uint32(i))
		case asm.DWord:
			return i
		}
		panic("unknown size")
	}

	b2i := func(b []byte) uint64 {
		switch size {
		case asm.Byte:
			return uint64(b[0])
		case asm.Half:
			return uint64(binary.BigEndian.Uint16(b))
		case asm.Word:
			return uint64(binary.BigEndian.Uint32(b))
		case asm.DWord:
			return binary.BigEndian.Uint64(b)
		}
		panic("unknown size")
	}

	switch offset {
	case 0 * 4: // __sk_buff->len
		if load {
			return toSize(uint64(sk.len)), nil
		}

		// len is readonly, https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8557
		return 0, errReadOnly

	case 1 * 4: // __sk_buff->pkt_type
		// https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/skbuff.h#L825
		const pktTypeMax = 7
		if load {
			// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8623
			return toSize(uint64(sk.pktType & pktTypeMax)), nil
		}

		// pkt_type is readonly https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8619
		return 0, errReadOnly

	case 2 * 4: // __sk_buff->mark
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8608
		if load {
			return toSize(uint64(sk.markOrReservedTailroom)), nil
		}

		sk.markOrReservedTailroom = uint32(toSize(value))
		return 0, nil

	case 3 * 4: // __sk_buff->queue_mapping
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8629
		if load {
			return toSize(uint64(sk.queueMapping)), nil
		}

		sk.queueMapping = uint16(toSize(value))
		return 0, nil
	case 4 * 4: // __sk_buff->protocol
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8563
		if load {
			return toSize(uint64(sk.protocol)), nil
		}

		// protocol is readonly
		return 0, errReadOnly

	case 5 * 4: // __sk_buff->vlan_present
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8644
		if load {
			if sk.vlanPresent {
				return 1, nil
			}

			return 0, nil
		}

		// vlan_present is readonly
		return 0, errReadOnly

	case 6 * 4: // __sk_buff->vlan_tci
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8654
		if load {
			return toSize(uint64(sk.vlanTCI)), nil
		}

		// vlan_tci is readonly
		return 0, errReadOnly

	case 7 * 4: // __sk_buff->vlan_proto
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8569
		if load {
			return toSize(uint64(sk.vlanProto)), nil
		}

		// vlan_proto is readonly
		return 0, errReadOnly

	case 8 * 4: // __sk_buff->priority
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8575
		if load {
			return toSize(uint64(sk.priority)), nil
		}

		sk.priority = uint32(toSize(value))
		return 0, nil

	case 9 * 4: // __sk_buff->ingress_ifindex
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8586
		if load {
			return toSize(uint64(sk.skbIIF)), nil
		}

		// ingress_ifindex is readonly
		return 0, errReadOnly

	case 10 * 4: // __sk_buff->ifindex
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8593
		if load {
			return toSize(uint64(sk.dev.IFIndex)), nil
		}

		// ifindex is readonly
		return 0, errReadOnly

	case 11 * 4: // __sk_buff->tc_index
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8720
		if load {
			return toSize(uint64(sk.tcIndex)), nil
		}

		sk.tcIndex = uint16(toSize(value))
		return 0, nil

	case 12*4 + 0, 12*4 + 1, 12*4 + 2, 12*4 + 3,
		13*4 + 0, 13*4 + 1, 13*4 + 2, 13*4 + 3,
		14*4 + 0, 14*4 + 1, 14*4 + 2, 14*4 + 3,
		15*4 + 0, 15*4 + 1, 15*4 + 2, 15*4 + 3,
		16*4 + 0, 16*4 + 1, 16*4 + 2, 16*4 + 3: // __u32 __sk_buff->cb[5]
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9819

		if load {
			val := sk.cb[offset:size.Sizeof()]
			return b2i(val), nil
		}

		val := make([]byte, size.Sizeof())
		switch size {
		case asm.Byte:
			val[0] = byte(value)
			return 0, nil
		case asm.Half:
			GetNativeEndianness().PutUint16(val, uint16(value))
			return 0, nil
		case asm.Word:
			GetNativeEndianness().PutUint32(val, uint32(value))
			return 0, nil
		case asm.DWord:
			GetNativeEndianness().PutUint64(val, value)
			return 0, nil
		}

		return 0, fmt.Errorf("unknown size")

	case 17 * 4: // __sk_buff->hash
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8602
		if load {
			return toSize(uint64(sk.hash)), nil
		}

		// hash is readonly
		return 0, errReadOnly

	case 18 * 4: // __sk_buff->tc_classid
		// https://elixir.bootlin.com/linux/v5.16.10/source/include/net/sch_generic.h#L442
		const tcClassIDOffset = 6

		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8602
		if load {
			return uint64(GetNativeEndianness().Uint16(sk.cb[tcClassIDOffset : tcClassIDOffset+2])), nil
		}

		GetNativeEndianness().PutUint16(sk.cb[tcClassIDOffset:tcClassIDOffset+2], uint16(value))
		return 0, nil

	case 19 * 4: // __sk_buff->data
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8696
		if load {
			return toSize(uint64(sk.data)), nil
		}

		// data is readonly
		return 0, errReadOnly

	case 20 * 4: // __sk_buff->data_end
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8711

		// https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/filter.h#L657
		// qdisc_skb_cb = 28 bytes
		// void *data_meta = is 8 bytes (on 64 bit systems)
		const dataEndOffset = 28 + 8

		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8602
		if load {
			return uint64(GetNativeEndianness().Uint16(sk.cb[dataEndOffset : dataEndOffset+2])), nil
		}

		// data_end is readonly
		return 0, errReadOnly

	case 21 * 4: // __sk_buff->napi_id
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8739
		if load {
			return toSize(uint64(sk.napiIDOrsenderCPU)), nil
		}

		// napi_id is readonly
		return 0, errReadOnly

	case 22 * 4: // __sk_buff->family
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8751
		if load {
			return toSize(uint64(sk.sk.Family)), nil
		}

		// family is readonly
		return 0, errReadOnly

	case 23*4 + 0, 23*4 + 1, 23*4 + 2, 23*4 + 3: // __sk_buff->remote_ip4
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8762
		if load {
			off := offset - 23*4
			v := make([]byte, size.Sizeof())
			copy(v, sk.sk.dstIP4[off:off+uint32(size.Sizeof())])
			return b2i(v), nil
		}

		// remote_ip4 is readonly
		return 0, errReadOnly

	case 24*4 + 0, 24*4 + 1, 24*4 + 2, 24*4 + 3: // __sk_buff->local_ip4
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8773
		if load {
			off := offset - 24*4
			v := make([]byte, size.Sizeof())
			copy(v, sk.sk.srcIP4[off:off+uint32(size.Sizeof())])
			return b2i(v), nil
		}

		// local_ip4 is readonly
		return 0, errReadOnly

	case 25*4 + 0, 25*4 + 1, 25*4 + 2, 25*4 + 3,
		26*4 + 0, 26*4 + 1, 26*4 + 2, 26*4 + 3,
		27*4 + 0, 27*4 + 1, 27*4 + 2, 27*4 + 3,
		28*4 + 0, 28*4 + 1, 28*4 + 2, 28*4 + 3: // __sk_buff->remote_ip6
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8785
		if load {
			off := offset - 25*4
			v := make([]byte, size.Sizeof())
			copy(v, sk.sk.dstIP6[off:off+uint32(size.Sizeof())])
			return b2i(v), nil
		}

		// remote_ip6 is readonly
		return 0, errReadOnly

	case 29*4 + 0, 29*4 + 1, 29*4 + 2, 29*4 + 3,
		30*4 + 0, 30*4 + 1, 30*4 + 2, 30*4 + 3,
		31*4 + 0, 31*4 + 1, 31*4 + 2, 31*4 + 3,
		32*4 + 0, 32*4 + 1, 32*4 + 2, 32*4 + 3: // __sk_buff->local_ip6
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8805
		if load {
			off := offset - 29*4
			v := make([]byte, size.Sizeof())
			copy(v, sk.sk.srcIP6[off:off+uint32(size.Sizeof())])
			return b2i(v), nil
		}

		// local_ip6 is readonly
		return 0, errReadOnly

	case 33 * 4: // __sk_buff->remote_port
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8826
		if load {
			return toSize(uint64(sk.sk.DstPort)), nil
		}

		// remote_port is readonly
		return 0, errReadOnly

	case 34 * 4: // __sk_buff->local_port
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8841
		if load {
			return toSize(uint64(sk.sk.SrcPort)), nil
		}

		// remote_port is readonly
		return 0, errReadOnly

	case 35 * 4: // __sk_buff->data_meta
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8702

		// https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/filter.h#L657
		// qdisc_skb_cb = 28 bytes
		const dataMetaOffset = 28 + 8

		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8602
		if load {
			return uint64(GetNativeEndianness().Uint16(sk.cb[dataMetaOffset : dataMetaOffset+2])), nil
		}

		// data_meta is readonly
		return 0, errReadOnly

	case 36 * 4, 37 * 4: // __sk_buff->flow_keys (__bpf_md_ptr(struct bpf_flow_keys *, flow_keys))
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8517
		if load {
			return uint64(sk.flowKeysAddr), nil
		}

		// flow_keys is readonly
		return 0, errReadOnly

	case 38 * 4, 39 * 4: // __u64 __sk_buff->tstamp
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8852
		if load {
			return uint64(sk.tstamp.Unix()), nil
		}

		sk.tstamp = time.Unix(int64(value), 0)
		return 0, nil

	case 40 * 4: // __sk_buff->wire_len
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8885

		// https://elixir.bootlin.com/linux/v5.16.10/source/include/net/sch_generic.h#L442
		const pktLenOffset = 0
		if load {
			return uint64(GetNativeEndianness().Uint32(sk.cb[pktLenOffset : pktLenOffset+4])), nil
		}

		// wire_len is readonly
		return 0, errReadOnly

	case 41 * 4: // __sk_buff->gso_segs
	// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8869
	// TODO required skb_shared_info

	case 42 * 4, 43 * 4: // __sk_buff->sk (__bpf_md_ptr(struct bpf_sock *, sk))
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8896
		if load {
			return uint64(sk.skAddr), nil
		}

		// sk is readonly
		return 0, errReadOnly

	case 44 * 4: // __sk_buff->gso_size
	// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8877
	// TODO required skb_shared_info

	// case 45 * 4: // Padding

	case 46 * 4, 47 * 4: // __u64 __sk_buff->hwtstamp
	// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8901
	// TODO required skb_shared_info

	default:
		return 0, fmt.Errorf("invalid offset '%d' into __sk_buff", offset)
	}

	return 0, fmt.Errorf("offset '%d' into __sk_buff not yet implemented", offset)
}

// Size returns the size of the __sk_buff (not the actual SKBuff, but its virtual address proxy range)
func (sk *SKBuff) Size() int {
	return 48 * 4
}

// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
func (sk *SKBuff) Read(offset uint32, b []byte) error {
	// Read is not used by the eBPF VM directly, only by helpers, so as long as helpers don't attempt to read from the
	// sk_buff, we should be good.
	return errors.New("not implemented")
}

// Write write a byte slice of arbitrary size to the memory
func (sk *SKBuff) Write(offset uint32, b []byte) error {
	// Write is not used by the eBPF VM directly, only by helpers, so as long as helpers don't attempt to read from the
	// sk_buff, we should be good.
	return errors.New("not implemented")
}

// SK https://elixir.bootlin.com/linux/v5.16.10/source/include/uapi/linux/bpf.h#L5406
type SK struct {
	BoundDevIF uint32 `json:"boundDevIF"`
	Family     uint32 `json:"family"`
	SockType   uint32 `json:"sockType"`
	Protocol   uint32 `json:"protocol"`
	Mark       uint32 `json:"mark"`
	Priority   uint32 `json:"priority"`

	SrcIP4         string `json:"srcIP4"`
	srcIP4         net.IP
	SrcIP6         string `json:"srcIP6"`
	srcIP6         net.IP
	SrcPort        uint32 `json:"srcPort"` /* host byte order */
	DstPort        uint32 `json:"dstPort"` /* network byte order */
	DstIP4         string `json:"dstIP4"`
	dstIP4         net.IP
	DstIP6         string `json:"dstIP6"`
	dstIP6         net.IP
	State          uint32 `json:"state"`
	RXQueueMapping int32  `json:"rxQueueMapping"`
}

// UnmarshalJSON implements json.Unmarshaler
func (sk *SK) UnmarshalJSON(b []byte) error {
	type Alias SK
	var a Alias
	err := json.Unmarshal(b, &a)
	if err != nil {
		return err
	}
	*sk = SK(a)

	sk.dstIP4 = make(net.IP, 4)
	sk.srcIP4 = make(net.IP, 4)
	sk.dstIP6 = make(net.IP, 16)
	sk.srcIP6 = make(net.IP, 16)

	if sk.DstIP4 != "" {
		if ip := net.ParseIP(sk.DstIP4); ip != nil {
			sk.dstIP4 = ip
		}
	}
	if sk.SrcIP4 != "" {
		if ip := net.ParseIP(sk.SrcIP4); ip != nil {
			sk.srcIP4 = ip
		}
	}
	if sk.DstIP6 != "" {
		if ip := net.ParseIP(sk.DstIP6); ip != nil {
			sk.dstIP6 = ip.To16()
		}
	}
	if sk.SrcIP6 != "" {
		if ip := net.ParseIP(sk.SrcIP6); ip != nil {
			sk.srcIP6 = ip.To16()
		}
	}

	return nil
}

// Load reads a single integer value of 1, 2, 4 or 8 bytes at a specific offset
func (sk *SK) Load(offset uint32, size asm.Size) (uint64, error) {
	return sk.convertAccess(offset, 0, size, true)
}

// Store write a single interger value of 1, 2, 4 or 8 bytes to a specific offset
func (sk *SK) Store(offset uint32, value uint64, size asm.Size) error {
	_, err := sk.convertAccess(offset, value, size, false)
	return err
}

// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8548
func (sk *SK) convertAccess(offset uint32, value uint64, size asm.Size, load bool) (uint64, error) {
	toSize := func(i uint64) uint64 {
		switch size {
		case asm.Byte:
			return uint64(uint8(i))
		case asm.Half:
			return uint64(uint16(i))
		case asm.Word:
			return uint64(uint32(i))
		case asm.DWord:
			return i
		}
		panic("unknown size")
	}
	b2i := func(b []byte) uint64 {
		switch size {
		case asm.Byte:
			return uint64(b[0])
		case asm.Half:
			return uint64(binary.BigEndian.Uint16(b))
		case asm.Word:
			return uint64(binary.BigEndian.Uint32(b))
		case asm.DWord:
			return binary.BigEndian.Uint64(b)
		}
		panic("unknown size")
	}

	switch offset {
	case 0 * 4: // bpf_sock->bound_dev_if
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8926
		if load {
			return toSize(uint64(sk.BoundDevIF)), nil
		}

		sk.BoundDevIF = uint32(toSize(value))
		return 0, nil

	case 1 * 4: // bpf_sock->family
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8959
		if load {
			return toSize(uint64(sk.Family)), nil
		}

		return 0, errReadOnly

	case 2 * 4: // bpf_sock->type
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8970
		if load {
			return toSize(uint64(sk.SockType)), nil
		}

		return 0, errReadOnly

	case 3 * 4: // bpf_sock->protocol
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8979
		if load {
			return toSize(uint64(sk.Protocol)), nil
		}

		return 0, errReadOnly

	case 4 * 4: // bpf_sock->mark
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8937
		if load {
			return toSize(uint64(sk.Mark)), nil
		}

		sk.Mark = uint32(toSize(value))
		return 0, nil

	case 5 * 4: // bpf_sock->priority
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8948
		if load {
			return toSize(uint64(sk.Priority)), nil
		}

		sk.Priority = uint32(toSize(value))
		return 0, nil

	case 6*4 + 0, 6*4 + 1, 6*4 + 2, 6*4 + 3: // bpf_sock->src_ipv4
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8988
		if !load {
			return 0, errReadOnly
		}

		v := make([]byte, size.Sizeof())
		start := offset - 6*4
		end := int(start) + size.Sizeof()
		copy(v, sk.srcIP4[start:end])
		return b2i(v), nil

	case 7*4 + 0, 7*4 + 1, 7*4 + 2, 7*4 + 3,
		8*4 + 0, 8*4 + 1, 8*4 + 2, 8*4 + 3,
		9*4 + 0, 9*4 + 1, 9*4 + 2, 9*4 + 3,
		10*4 + 0, 10*4 + 1, 10*4 + 2, 10*4 + 3: // bpf_sock->src_ipv6
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9006
		if !load {
			return 0, errReadOnly
		}

		v := make([]byte, size.Sizeof())
		start := offset - 7*4
		end := int(start) + size.Sizeof()
		copy(v, sk.srcIP6[start:end])
		return b2i(v), nil

	case 11 * 4: // bpf_sock->src_port
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9041
		if load {
			return toSize(uint64(sk.SrcPort)), nil
		}

		return 0, errReadOnly

	case 12 * 4: // bpf_sock->dst_port
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9051
		if load {
			return toSize(uint64(sk.DstPort)), nil
		}

		return 0, errReadOnly

	case 13*4 + 0, 13*4 + 1, 13*4 + 2, 13*4 + 3: // bpf_sock->dst_ipv4
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L8997
		if !load {
			return 0, errReadOnly
		}

		v := make([]byte, size.Sizeof())
		start := offset - 13*4
		end := int(start) + size.Sizeof()
		copy(v, sk.dstIP4[start:end])
		return b2i(v), nil

	case 14*4 + 0, 14*4 + 1, 14*4 + 2, 14*4 + 3,
		15*4 + 0, 15*4 + 1, 15*4 + 2, 15*4 + 3,
		16*4 + 0, 16*4 + 1, 16*4 + 2, 16*4 + 3,
		17*4 + 0, 17*4 + 1, 17*4 + 2, 17*4 + 3: // bpf_sock->dst_ipv6
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9024
		if !load {
			return 0, errReadOnly
		}

		v := make([]byte, size.Sizeof())
		start := offset - 17*4
		end := int(start) + size.Sizeof()
		copy(v, sk.dstIP6[start:end])
		return b2i(v), nil

	case 18 * 4: // bpf_sock->state
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9061
		if load {
			return toSize(uint64(sk.State)), nil
		}

		return 0, errReadOnly

	case 19 * 4: // bpf_sock->rx_queue_mapping
		// https://elixir.bootlin.com/linux/v5.16.10/source/net/core/filter.c#L9070
		if load {
			return toSize(uint64(sk.RXQueueMapping)), nil
		}

		return 0, errReadOnly

	default:
		return 0, fmt.Errorf("invalid offset '%d' into __sk_buff", offset)
	}
}

// Size returns the size of the bpf_sk (not the actual sk, but its virtual address proxy range)
func (sk *SK) Size() int {
	return 20 * 4
}

// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
func (sk *SK) Read(offset uint32, b []byte) error {
	// Read is not used by the eBPF VM directly, only by helpers, so as long as helpers don't attempt to read from the
	// sk_buff, we should be good.
	return errors.New("not implemented")
}

// Write write a byte slice of arbitrary size to the memory
func (sk *SK) Write(offset uint32, b []byte) error {
	// Write is not used by the eBPF VM directly, only by helpers, so as long as helpers don't attempt to read from the
	// sk_buff, we should be good.
	return errors.New("not implemented")
}

// NetDev represents a network device to which a socket / socket_buffer is connected
type NetDev struct {
	IFIndex uint32 `json:"ifIndex"`
}

// FlowKeys describe the flow information of a sk_buff
type FlowKeys struct {
	Nhoff uint16 `json:"nhoff"`
	Thoff uint16 `json:"thoff"`
	// ETH_P_* of valid addrs
	AddrProto     uint16 `json:"addrProto"`
	IsFrag        uint8  `json:"isFrag"`
	IsFirstFrag   uint8  `json:"isFirstFrag"`
	IsEncap       uint8  `json:"isEncap"`
	IPProto       uint8  `json:"ipProto"`
	NProto        uint16 `json:"nProto"`
	Sport         uint16 `json:"sport"`
	Dport         uint16 `json:"dport"`
	SrcIPv6orIPv4 net.IP `json:"ip"`
	Flags         uint32 `json:"flags"`
	FlowLabel     uint32 `json:"flowLabel"`
}

// Load reads a single integer value of 1, 2, 4 or 8 bytes at a specific offset
func (fk *FlowKeys) Load(offset uint32, size asm.Size) (uint64, error) {
	return fk.convertAccess(offset, 0, size, true)
}

// Store write a single interger value of 1, 2, 4 or 8 bytes to a specific offset
func (fk *FlowKeys) Store(offset uint32, value uint64, size asm.Size) error {
	_, err := fk.convertAccess(offset, value, size, false)
	return err
}

func (fk *FlowKeys) convertAccess(offset uint32, value uint64, size asm.Size, load bool) (uint64, error) {
	toSize := func(i uint64) uint64 {
		switch size {
		case asm.Byte:
			return uint64(uint8(i))
		case asm.Half:
			return uint64(uint16(i))
		case asm.Word:
			return uint64(uint32(i))
		case asm.DWord:
			return i
		}
		panic("unknown size")
	}
	b2i := func(b []byte) uint64 {
		switch size {
		case asm.Byte:
			return uint64(b[0])
		case asm.Half:
			return uint64(binary.BigEndian.Uint16(b))
		case asm.Word:
			return uint64(binary.BigEndian.Uint32(b))
		case asm.DWord:
			return binary.BigEndian.Uint64(b)
		}
		panic("unknown size")
	}

	switch offset {
	case 0, 1: // bpf_flow_keys->nhoff
		if load {
			return toSize(uint64(fk.Nhoff)), nil
		}

		fk.Nhoff = uint16(toSize(value))
		return 0, nil

	case 2, 3: // bpf_flow_keys->thoff
		if load {
			return toSize(uint64(fk.Thoff)), nil
		}

		fk.Thoff = uint16(toSize(value))
		return 0, nil

	case 4, 5: // bpf_flow_keys->addr_proto
		if load {
			return toSize(uint64(fk.AddrProto)), nil
		}

		fk.AddrProto = uint16(toSize(value))
		return 0, nil

	case 6: // bpf_flow_keys->is_frag
		if load {
			return toSize(uint64(fk.IsFrag)), nil
		}

		fk.IsFrag = uint8(toSize(value))
		return 0, nil

	case 7: // bpf_flow_keys->is_first_frag
		if load {
			return toSize(uint64(fk.IsFirstFrag)), nil
		}

		fk.IsFirstFrag = uint8(toSize(value))
		return 0, nil

	case 8: // bpf_flow_keys->is_encap
		if load {
			return toSize(uint64(fk.IsEncap)), nil
		}

		fk.IsEncap = uint8(toSize(value))
		return 0, nil

	case 9: // bpf_flow_keys->ip_proto
		if load {
			return toSize(uint64(fk.IPProto)), nil
		}

		fk.IPProto = uint8(toSize(value))
		return 0, nil

	case 10, 11: // bpf_flow_keys->n_proto
		if load {
			return toSize(uint64(fk.NProto)), nil
		}

		fk.NProto = uint16(toSize(value))
		return 0, nil

	case 12, 13: // bpf_flow_keys->sport
		if load {
			return toSize(uint64(fk.Sport)), nil
		}

		fk.Sport = uint16(toSize(value))
		return 0, nil

	case 14, 15: // bpf_flow_keys->dport
		if load {
			return toSize(uint64(fk.Dport)), nil
		}

		fk.Dport = uint16(toSize(value))
		return 0, nil

	case 16 + 0, 16 + 1, 16 + 2, 16 + 3,
		16 + 4, 16 + 5, 16 + 6, 16 + 7,
		16 + 8, 16 + 9, 16 + 10, 16 + 11,
		16 + 12, 16 + 13, 16 + 14, 16 + 15: // bpf_flow_keys->{ipv4_dst,ipv4_src,ipv6_dst,ipv6_src}
		ip := make(net.IP, 16)
		copy(ip, fk.SrcIPv6orIPv4)
		if load {
			return b2i(ip[offset : offset+uint32(size.Sizeof())]), nil
		}

		switch size {
		case asm.Byte:
			ip[offset] = byte(value)
		case asm.Half:
			GetNativeEndianness().PutUint16(ip[offset:], uint16(value))
		case asm.Word:
			GetNativeEndianness().PutUint32(ip[offset:], uint32(value))
		case asm.DWord:
			GetNativeEndianness().PutUint64(ip[offset:], value)
		}
		fk.SrcIPv6orIPv4 = ip

		return 0, nil

	case 32, 33, 34, 35: // bpf_flow_keys->flags
		if load {
			return toSize(uint64(fk.Flags)), nil
		}

		fk.Flags = uint32(toSize(value))
		return 0, nil

	case 36, 37, 38, 39: // bpf_flow_keys->flow_label
		if load {
			return toSize(uint64(fk.FlowLabel)), nil
		}

		fk.FlowLabel = uint32(toSize(value))
		return 0, nil
	}

	return 0, fmt.Errorf("invalid offset '%d' into bpf_flow_keys", offset)
}

// Read reads a byte slice of arbitrary size, the length of 'b' is used to determine the requested size
func (fk *FlowKeys) Read(offset uint32, b []byte) error {
	// Read is not used by the eBPF VM directly, only by helpers, so as long as helpers don't attempt to read from the
	// sk_buff, we should be good.
	return errors.New("not implemented")
}

// Write write a byte slice of arbitrary size to the memory
func (fk *FlowKeys) Write(offset uint32, b []byte) error {
	// Write is not used by the eBPF VM directly, only by helpers, so as long as helpers don't attempt to read from the
	// sk_buff, we should be good.
	return errors.New("not implemented")
}

// Size returns the size of a flowKeys struct in bytes
func (fk *FlowKeys) Size() int {
	return 40
}

type skBuffPktType uint8

// https://elixir.bootlin.com/linux/v5.16.10/source/include/uapi/linux/if_packet.h#L29
const skBuffPktTypeOtherhost = 3

func (pt skBuffPktType) valid() bool {
	return pt <= skBuffPktTypeOtherhost
}
