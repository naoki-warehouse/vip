module main

import net.conv

[packed]
struct EthHdr {
    dmac PhysicalAddress
    smac PhysicalAddress
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