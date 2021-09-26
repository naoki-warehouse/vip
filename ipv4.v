module main

struct IPv4Hdr {
    version u8 = 4
mut:
    header_length u8 = 20
    tos u8
    total_len u16
    id u16
    frag_flag u8
    frag_offset u16
    ttl u8
    protocol u8
    chksum u16
    src_addr IPv4Address
    dst_addr IPv4Address
}

enum IPv4Protocol {
    icmp = 1
    tcp = 6
    udp = 17
}

fn parse_ipv4_hdr(buf []byte) ?IPv4Hdr {
    assert buf.len >= 20

    return IPv4Hdr {
        version : (buf[0] >> 4) & 0xF
        header_length : ((buf[0]) & 0xF) * 4
        tos : buf[1]
        total_len : be16(buf[2..4]) 
        id : be16(buf[4..6])
        frag_flag : (buf[6] >> 5) & 0b111
        frag_offset : (((buf[6] & 0b11111) << 8) | buf[7]) * 8
        ttl : buf[8]
        protocol : buf[9]
        chksum : be16(buf[10..12])
        src_addr : parse_ipv4_address(buf[12..16])
        dst_addr : parse_ipv4_address(buf[16..20])
    }
}

fn (ip IPv4Hdr) to_bytes() []byte {
    mut buf := []byte{len:20}
    buf[0] = byte((ip.version << 4) | (ip.header_length >> 2))
    buf[1] = ip.tos
    copy(buf[2..4], be_u16_to_bytes(ip.total_len))
    copy(buf[4..6], be_u16_to_bytes(ip.id))
    buf[6] = byte((ip.frag_flag << 5) & 0xFF)
    buf[6] |= byte(((ip.frag_offset/8) >> 8)& 0b11111)
    buf[7] = byte(ip.frag_offset/8)
    buf[8] = ip.ttl
    buf[9] = ip.protocol
    copy(buf[10..12], be_u16_to_bytes(ip.chksum))
    copy(buf[12..16], ip.src_addr.addr[0..4])
    copy(buf[16..20], ip.dst_addr.addr[0..4])

    return buf
}

fn (ip IPv4Hdr) to_string() string {
    mut s := "Version:$ip.version "
    s += "Hdr Length:$ip.header_length "
    s += "TOS:0x${ip.tos:04X} "
    s += "Total Length:$ip.total_len "
    s += "ID:0x${ip.id:04X} "
    s += "Fragment Flag:0b${ip.frag_flag:03b} "
    s += "Fragment Offset:${ip.frag_offset} "
    s += "TTL:${ip.ttl} "
    s += "Protocol:${ip.protocol} "
    s += "CheckSum:0x${ip.chksum:04X} "
    s += "SrcAddr:${ip.src_addr.to_string()} "
    s += "DstAddr:${ip.dst_addr.to_string()}"
    return s
}