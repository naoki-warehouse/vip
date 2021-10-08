module main

struct IPv6Hdr {
    version byte = 6
mut:
    traffic_class byte
    flow_label u32
    payload_length u16
    next_header byte
    hop_limit byte
    src_addr IPv6Address
    dst_addr IPv6Address

    protocol IPv6Protocol
    hdr_len int
}

enum IPv6Protocol {
    icmpv6 = 58
}

fn parse_ipv6_hdr(buf []byte) ?IPv6Hdr {
    assert buf.len >= 8

    mut hdr := IPv6Hdr {
        version : (buf[0] >> 4) & 0xF
        traffic_class : ((buf[0] & 0xF) << 4) | ((buf[1] >> 4) & 0xF)
        flow_label : ((buf[1] & 0xF) << 16) | (buf[2] << 8) | buf[3]
        payload_length : be16(buf[4..6])
        next_header : buf[6]
        hop_limit : buf[7]
        src_addr : parse_ipv6_address(buf[8..24])
        dst_addr : parse_ipv6_address(buf[24..40])
    }

    if hdr.next_header == byte(IPv6Protocol.icmpv6) {
        hdr.protocol = IPv6Protocol.icmpv6
    }

    hdr.hdr_len = 40

    return hdr
}

fn (ip6 &IPv6Hdr) to_bytes() []byte {
    mut buf := []byte{len:40}

    buf[0] = (ip6.version << 4) | (ip6.traffic_class >> 4)
    buf[1] = byte(((ip6.traffic_class & 0xF) << 4) | ((ip6.flow_label >> 16) & 0xF))
    buf[2] = byte((ip6.flow_label >> 8))
    buf[3] = byte(ip6.flow_label)
    copy(buf[4..6], be_u16_to_bytes(ip6.payload_length))
    buf[6] = ip6.next_header
    buf[7] = ip6.hop_limit
    copy(buf[8..24], ip6.src_addr.addr[0..])
    copy(buf[24..40], ip6.dst_addr.addr[0..])

    return buf
}

fn (ip6 &IPv6Hdr) to_string() string {
    mut s := "Version:$ip6.version "
    s += "TrafficClass:0x${ip6.flow_label:x} "
    s += "FlowLabel:0x${ip6.flow_label} "
    s += "PayloadLength:${ip6.payload_length} "
    s += "NextHeader:${ip6.next_header} "
    s += "HopLimit:${ip6.hop_limit} "
    s += "SrcAddr:${ip6.src_addr.to_string()} "
    s += "DstAddr:${ip6.dst_addr.to_string()}"
    return s
}
