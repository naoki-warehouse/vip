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