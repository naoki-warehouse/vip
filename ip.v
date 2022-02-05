module main

import net.conv

[packed]
struct IpHdrBase {
    vh u8
    tos u8
    total_len u16
    id u16
    fragment u16
    ttl u8
mut:
    protocol u8
    chksum u16
    src_addr IpAddress
    dst_addr IpAddress
}

struct IpHdr {
	base &IpHdrBase
}

fn (ip &IpHdrBase) get_version() int {
	return (ip.vh >> 4)
}

fn (ip &IpHdrBase) get_header_length() int {
	return (ip.vh & 0xF) * 4
}

fn parse_ip_header(buf []byte) ?&IpHdr {
    assert buf.len >= sizeof(IpHdrBase)

    ip_base := unsafe { &IpHdrBase(&buf[0]) }
    return &IpHdr{
        base: ip_base
    }
}
fn (ip &IpHdr) len() int {
	return 20
}

fn (ip &IpHdrBase) write_bytes(mut buf []byte) ?int {
    assert buf.len >= 20
    mut offset := 0
    buf[offset] = ip.vh
    offset += 1
    buf[offset] = ip.tos
    offset += 1
    offset += copy(buf[offset..], le_u16_to_bytes(ip.total_len))
    offset += copy(buf[offset..], le_u16_to_bytes(ip.id))
    offset += copy(buf[offset..], le_u16_to_bytes(ip.fragment))
    buf[offset] = ip.ttl
    offset += 1
    buf[offset] = ip.protocol
    offset += 1
    chksum_offset := offset
    offset += copy(buf[offset..], le_u16_to_bytes(0))
    offset += copy(buf[offset..], ip.src_addr.addr[0..])
    offset += copy(buf[offset..], ip.dst_addr.addr[0..])

    chksum := calc_chksum(buf[0..offset])
    copy(buf[chksum_offset..], be_u16_to_bytes(chksum))

    return offset
}

fn (ip &IpHdr) write_bytes(mut buf []byte) ?int {
    return ip.base.write_bytes(mut buf)
}

fn (ip &IpHdrBase) str() string {
	mut s := ""
	s += "version:${ip.get_version()} "
	s += "header_length:${ip.get_header_length()} "
    s += "total_len:${conv.nth16(ip.total_len)} "
    s += "ttl:${ip.ttl} "
    s += "chksum:0x${ip.chksum:04X} "
    s += "protocol:${ip.protocol} "
    s += "src_addr:${ip.src_addr} "
    s += "dst_addr:${ip.dst_addr}"
	return s
}

fn (mut nd NetDevice) handle_ip(pkt &Packet, ip &IpHdr, mut sock_addr SocketAddress) {
	l4_hdr := pkt.l4_hdr
	match l4_hdr {
		HdrNone {

		}
		IcmpHdr {
			nd.handle_icmp(pkt, l4_hdr, mut sock_addr)
		}
	}
}

fn (mut nd NetDevice) send_ip(mut pkt Packet, dst_addr &SocketAddress)? {
	mut ip_hdr_base := &IpHdrBase {
		vh: (4 << 4) | (5)
		tos: 0
		total_len: conv.htn16(u16(20 + pkt.l4_hdr.len() + pkt.payload.len))
		id: 0x1234
		fragment: 0
		ttl: 64
		protocol: 0
		chksum: 0
		src_addr: nd.ip_addr
		dst_addr: dst_addr.ip_addr
	}

	l4_hdr := pkt.l4_hdr
	match l4_hdr {
		HdrNone {
			panic("l4_hdr is not set")
		}
		IcmpHdr {
			ip_hdr_base.protocol = 1
		}
	}

	pkt.l3_hdr = &IpHdr {
		base: ip_hdr_base
	}

	return nd.send_ethernet(mut pkt, dst_addr)
}
