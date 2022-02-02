module main

import net.conv

[packed]
struct ArpHdr {
    hw_type u16
    proto_type u16
    hw_size u8
    proto_size u8
    op u16
    sha PhysicalAddress
    spa IpAddress
    tha PhysicalAddress
    tpa IpAddress
}

enum ArpHWType {
    ethernet = 0x0001
}

enum ArpProtoType {
    ipv4 = 0x0800
}

enum ArpOpcode {
    request = 0x0001
    reply = 0x0002
}

fn parse_arp_header(buf []byte) ?&ArpHdr {
    assert buf.len >= sizeof(ArpHdr)

    return unsafe { &ArpHdr(&buf[0])}
}

fn (ap &ArpHdr) len() int {
    return int(sizeof(ArpHdr))
}

fn (ap &ArpHdr) str() string {
    mut s := "hw_type:"
    hw_type := conv.nth16(ap.hw_type)
    if hw_type == u16(ArpHWType.ethernet) {
        s += "Ethernet "
    } else {
        s += "0x${hw_type} "
    }

    proto_type := conv.nth16(ap.proto_type)
    s += "proto_type:"
    if proto_type == u16(ArpProtoType.ipv4) {
        s += "IPv4 "
    } else {
        s += "0x${proto_type} "
    }

    op := conv.nth16(ap.op)
    s += "op:"
    if op == u16(ArpOpcode.request) {
        s += "Request "
    } else if op == u16(ArpOpcode.reply) {
        s += "Reply "
    }

    s += "sha:${ap.sha} "
    s += "spa:${ap.spa} "
    s += "tha:${ap.tha} "
    s += "tpa:${ap.tpa}"

    return s
}

fn (ap &ArpHdr) write_bytes(mut buf []byte) ?int {
    assert buf.len >= ap.len()
    mut offset := 0
    offset += copy(buf[offset..], le_u16_to_bytes(ap.hw_type))
    offset += copy(buf[offset..], le_u16_to_bytes(ap.proto_type))
    buf[offset] = ap.hw_size
    offset += 1
    buf[offset] = ap.proto_size
    offset += 1
    offset += copy(buf[offset..], le_u16_to_bytes(ap.op))
    offset += copy(buf[offset..], ap.sha.addr[0..])
    offset += copy(buf[offset..], ap.spa.addr[0..])
    offset += copy(buf[offset..], ap.tha.addr[0..])
    offset += copy(buf[offset..], ap.tpa.addr[0..])

    return offset
}
