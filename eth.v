module main

struct EthHdr {
mut:
    dmac PhysicalAddress
    smac PhysicalAddress
    ether_type u16
}

enum EtherType {
    arp = 0x0806
    ipv4 = 0x0800
    ipv6 = 0x86DD
}

fn (e EthHdr) to_string() string {
    mut s := "DestMAC:${e.dmac.to_string()} "
    s += "SrcMAC:${e.smac.to_string()} "
    s += "EtherType: 0x${e.ether_type:02X}"
    return s
}

fn (e EthHdr) to_bytes() []byte {
    mut buf := []byte{len: 14}
    copy(buf[0..6], e.dmac.addr[0..6])
    copy(buf[6..12], e.smac.addr[0..6])
    copy(buf[12..14], be_u16_to_bytes(e.ether_type))

    return buf
}


fn parse_eth_hdr(buf []byte) ?EthHdr {
    if buf.len < int(sizeof(EthHdr)){
        return error("recv size is too small $buf.len")
    }

    eth_hdr := EthHdr{
        dmac : parse_physical_address(buf[0..6])
        smac : parse_physical_address(buf[6..12])
        ether_type : be16(buf[12..14])
    }

    return eth_hdr
}

