module main

struct UdpHdr {
mut:
    src_port u16
    dst_port u16
    segment_length u16
    chksum u16
}

fn parse_udp_hdr(buf []byte) ?UdpHdr {
    assert buf.len >= 8

    return UdpHdr {
        src_port : be16(buf[0..2])
        dst_port : be16(buf[2..4])
        segment_length : be16(buf[4..6])
        chksum : be16(buf[6..8])
    }
}

fn (udp UdpHdr) to_bytes() []byte {
    mut buf := []byte{len: 8}
    buf[0] = byte(udp.src_port >> 8)
    buf[1] = byte(udp.src_port)
    buf[2] = byte(udp.dst_port >> 8)
    buf[3] = byte(udp.dst_port)
    buf[4] = byte(udp.segment_length >> 8)
    buf[5] = byte(udp.segment_length)
    buf[6] = byte(udp.chksum >> 8)
    buf[7] = byte(udp.chksum)

    return buf
}

fn (udp UdpHdr) len() int {
    return 8
}