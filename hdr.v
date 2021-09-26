module main

import time

struct HdrNone {}

fn (hn HdrNone) len() int {
    return 0
}

type L3Hdr = HdrNone | ArpHdr | IPv4Hdr
type L4Hdr = HdrNone | IcmpHdr | UdpHdr

struct Packet {
mut:
    sockfd int
    l2_hdr EthHdr
    l3_hdr L3Hdr
    l4_hdr L4Hdr
    payload []byte

    timestamp time.Time
}


struct PseudoHdr {
    src_ip IPv4Address
    dst_ip IPv4Address
    protocol u8
    udp_length u16
}

fn (ph PseudoHdr) to_bytes() []byte {
    mut buf := []byte{len: 12}
    copy(buf[0..4], ph.src_ip.addr[0..4])
    copy(buf[4..8], ph.dst_ip.addr[0..4])
    buf[8] = 0
    buf[9] = ph.protocol
    copy(buf[10..12], be_u16_to_bytes(ph.udp_length))

    return buf
}

fn parse_eth_frame(mut pkt Packet, buf[]byte) ? {
    eth_hdr := parse_eth_hdr(buf) ?
    pkt.l2_hdr = eth_hdr
    if eth_hdr.ether_type == u16(EtherType.arp) {
        return parse_arp_packet(mut pkt, buf[14..])
    } else if eth_hdr.ether_type == u16(EtherType.ipv4) {
        return parse_ipv4_packet(mut pkt, buf[14..])
    }

    return error("unknown EtherType:0x${eth_hdr.ether_type:04X}")
}

fn parse_arp_packet(mut pkt Packet, buf []byte) ? {
    arp_hdr := parse_arp_hdr(buf) ?
    pkt.l3_hdr = arp_hdr
}

fn parse_ipv4_packet(mut pkt Packet, buf []byte) ? {
    ipv4_hdr := parse_ipv4_hdr(buf) ?
    pkt.l3_hdr = ipv4_hdr
    if ipv4_hdr.protocol == byte(IPv4Protocol.icmp) {
        return parse_icmp_packet(mut pkt, buf[int(ipv4_hdr.header_length)..])
    }

    return error("unknown protocol:${ipv4_hdr.protocol}")
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

fn (l3_hdr &L3Hdr) get_ipv4_hdr() ?IPv4Hdr {
    match l3_hdr {
        IPv4Hdr {
            return l3_hdr
        }
        else {
            return error("not arp header")
        }
    }
}

fn (pkt &Packet) is_icmp_packet() bool {
    match pkt.l4_hdr {
        IcmpHdr {
            return true
        }
        else {
            return false
        }
    }
}