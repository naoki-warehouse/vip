module main

struct HdrNone {}

fn (hn HdrNone) len() int {
    return 0
}

type L3Hdr = HdrNone | ArpHdr | IPv4Hdr
type L4Hdr = HdrNone | IcmpHdr | UdpHdr

struct Packet {
mut:
    l2_hdr EthHdr
    l3_hdr L3Hdr
    l4_hdr L4Hdr
    payload []byte
}


struct PseudoHdr {
    src_ip IPv4Address
    dst_ip IPv4Address
    protocol u8
    udp_length u16
}

fn (ph PseudoHdr) to_bytes() []byte {
    mut buf := []byte{len: 12}

    for i := 0; i < 4; i += 1 {
        buf[i] = ph.src_ip.addr[i]
    }
    for i := 0; i < 4; i += 1 {
        buf[4+i] = ph.dst_ip.addr[i]
    }
    buf[8] = 0
    buf[9] = ph.protocol
    buf[10] = byte(ph.udp_length >> 8)
    buf[11] = byte(ph.udp_length)

    return buf
}

fn parse_ipv4_packet(mut pkt Packet, buf []byte) ? {
    ipv4_hdr := parse_ipv4_hdr(buf) ?
    pkt.l3_hdr = ipv4_hdr
    if ipv4_hdr.protocol == byte(IPv4Protocol.icmp) {
        parse_icmp_hdr(buf[int(ipv4_hdr.header_length)..]) ?
    }
}

fn parse_icmp_packet(mut pkt Packet, buf []byte) ? {
    icmp_hdr := parse_icmp_hdr(buf) ?
    pkt.l4_hdr = icmp_hdr
    pkt.payload = buf[icmp_hdr.len()..]
}

fn (l3_hdr &L3Hdr) to_string() string {
    match l3_hdr {
        IPv4Hdr {
            return l3_hdr.to_string()
        }
        ArpHdr {
            return l3_hdr.to_string()
        }
        HdrNone {
            return ""
        }
    }
}

fn (l4_hdr &L4Hdr) to_string() string {
    match l4_hdr {
        IcmpHdr{
            return l4_hdr.to_string()
        }
        UdpHdr {
            return ""
        }
        HdrNone {
            return ""
        }
    }
}