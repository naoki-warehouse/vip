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
