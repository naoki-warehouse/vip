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
    copy(buf[0..2], be_u16_to_bytes(udp.src_port))
    copy(buf[2..4], be_u16_to_bytes(udp.dst_port))
    copy(buf[4..6], be_u16_to_bytes(udp.segment_length))
    copy(buf[6..8], be_u16_to_bytes(udp.chksum))

    return buf
}

fn (udp UdpHdr) len() int {
    return 8
}