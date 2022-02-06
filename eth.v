module main

import net.conv

[packed]
struct EthHdr {
    dmac PhysicalAddress
    smac PhysicalAddress
mut:
    ether_type u16
}

fn parse_ethernet_header(buf []byte) ?&EthHdr {
	assert buf.len >= sizeof(EthHdr)
	return unsafe { &EthHdr(&buf[0]) }
}

fn (eh &EthHdr) str() string {
	mut s := "dst_mac:${eh.dmac} "
	s += "src_mac:${eh.smac} "
	s += "ether_type:0x${conv.nth16(eh.ether_type):04X}"
	return s
}

fn (eh &EthHdr) len() int {
	return int(sizeof(EthHdr))
}

fn (eh &EthHdr) write_bytes(mut buf []byte) ?int {
	assert buf.len >= eh.len()
	mut offset := 0
	offset += copy(buf[offset..], eh.dmac.addr[0..])
	offset += copy(buf[offset..], eh.smac.addr[0..])
	offset += copy(buf[offset..], le_u16_to_bytes(eh.ether_type))

	return offset
}

fn (nd &NetDevice) create_ethernet(mut pkt Packet, dst_addr &SocketAddress)? {
	mut l2_hdr := &EthHdr {
		dmac: dst_addr.physical_addr
		smac: nd.physical_addr
	}

	l3_hdr := pkt.l3_hdr
	match l3_hdr {
		HdrNone {
			panic("l3_hdr is not set")
		}
		ArpHdr {
			l2_hdr.ether_type = conv.htn16(0x0806)
		}
		IpHdr {
			l2_hdr.ether_type = conv.htn16(0x0800)
		}
	}
	pkt.l2_hdr = l2_hdr
}


fn (sock &Socket) create_ethernet(mut pkt Packet, dst_addr &SocketAddress)? {
	mut l2_hdr := &EthHdr {
		dmac: dst_addr.physical_addr
		smac: sock.my_physical_addr
	}

	l3_hdr := pkt.l3_hdr
	match l3_hdr {
		HdrNone {
			panic("l3_hdr is not set")
		}
		ArpHdr {
			l2_hdr.ether_type = conv.htn16(0x0806)
		}
		IpHdr {
			l2_hdr.ether_type = conv.htn16(0x0800)
		}
	}
	pkt.l2_hdr = l2_hdr
}

