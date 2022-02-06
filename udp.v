module main

import net.conv

[packed]
struct UdpHdr {
	src_port       u16
	dst_port       u16
	segment_length u16
	chksum         u16
}

fn parse_udp_header(buf []byte) ?&UdpHdr {
	assert buf.len >= sizeof(UdpHdr)

	return unsafe { &UdpHdr(&buf[0]) }
}

fn (uh &UdpHdr) len() int {
	return int(sizeof(UdpHdr))
}

fn (uh &UdpHdr) str() string {
	mut s := 'src_port: ${conv.nth16(uh.src_port)} '
	s += 'dst_port: ${conv.nth16(uh.dst_port)} '
	s += 'len: ${conv.nth16(uh.segment_length)}'
	s += 'chksum: 0x${uh.chksum:04X}'
	return s
}

fn (uh &UdpHdr) write_bytes(mut buf []byte) ?int {
	assert buf.len >= uh.len()
	mut offset := 0
	offset += copy(buf[offset..], le_u16_to_bytes(uh.src_port))
	offset += copy(buf[offset..], le_u16_to_bytes(uh.dst_port))
	offset += copy(buf[offset..], le_u16_to_bytes(uh.segment_length))
	offset += copy(buf[offset..], le_u16_to_bytes(uh.chksum))

	return offset
}

fn (sock &Socket) create_udp(payload []byte, dst_addr &SocketAddress) ?Packet {
	length := u16(int(sizeof(UdpHdr)) + payload.len)
	chksum := calc_pseudo_header(&sock.my_ip_addr, &dst_addr.ip_addr, 17, length)
	mut pkt := Packet{
		l2_hdr: &HdrNone{}
		l3_hdr: &HdrNone{}
		l4_hdr: &UdpHdr{
			src_port: conv.htn16(4321)
			dst_port: conv.htn16(dst_addr.port)
			segment_length: conv.htn16(length)
			chksum: conv.htn16(chksum)
		}
		payload: payload
	}
	sock.create_ip(mut pkt, dst_addr) ?
	return pkt
}
