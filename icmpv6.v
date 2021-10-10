module main

struct Icmpv6HdrBase {
mut:
    icmpv6_type byte
    code byte
    chksum u16
}

type Icmpv6HdrType = Icmpv6HdrBase | Icmpv6HdrNeighborSolicitation | Icmpv6HdrNeighborAdvertisement | Icmpv6HdrEcho

struct Icmpv6Hdr {
mut:
    hdr Icmpv6HdrType
}

struct Icmpv6HdrNeighborSolicitation {
    Icmpv6HdrBase
    target_address IPv6Address
mut:
    option Icmpv6OptionLinkLayerAddress
}

struct Icmpv6HdrNeighborAdvertisement {
    Icmpv6HdrBase
    target_address IPv6Address
    flag_router bool
    flag_solicited bool
    flag_override bool
mut:
    option Icmpv6OptionLinkLayerAddress
}

struct Icmpv6OptionLinkLayerAddress {
    option_type byte
    length int
    link_addr PhysicalAddress
}

struct Icmpv6HdrEcho {
    Icmpv6HdrBase
    id u16
    seq_num u16
}

enum Icmpv6Type {
    echo_request = 128
    echo_reply = 129
    neighbor_solicitation = 135
    neighbor_advertisement = 136
}

enum Icmpv6Option {
    source_linklayer_address = 1
    target_linklayer_address = 2
}

fn parse_icmpv6_hdr(buf []byte) ?Icmpv6Hdr {
    assert buf.len >= 4

    hdr_base := Icmpv6HdrBase {
        icmpv6_type : buf[0]
        code : buf[1]
        chksum : be16(buf[2..4])
    }

    if hdr_base.icmpv6_type == byte(Icmpv6Type.neighbor_solicitation) {
        mut hdr := Icmpv6HdrNeighborSolicitation {
            Icmpv6HdrBase: hdr_base
            target_address: parse_ipv6_address(buf[8..24])
        }
        if  buf.len >= 32 {
            lla := Icmpv6OptionLinkLayerAddress {
                option_type : buf[24]
                length: buf[25] * 8
                link_addr: parse_physical_address(buf[26..32])
            }
            hdr.option = lla
        }

        return Icmpv6Hdr {
            hdr : hdr
        }
    }
    if hdr_base.icmpv6_type == byte(Icmpv6Type.neighbor_advertisement) {
        mut hdr := Icmpv6HdrNeighborAdvertisement {
            Icmpv6HdrBase: hdr_base
            target_address: parse_ipv6_address(buf[8..24])
            flag_router: ((buf[24] >> 7) & 1) == 1
            flag_solicited: ((buf[24] >> 6) & 1) == 1
            flag_override: ((buf[24] >> 5) & 1) == 1
        }
        if  buf.len >= 32 {
            lla := Icmpv6OptionLinkLayerAddress {
                option_type : buf[24]
                length: buf[25] * 8
                link_addr: parse_physical_address(buf[26..32])
            }
            hdr.option = lla
        }

        return Icmpv6Hdr {
            hdr : hdr
        }
    }

    if hdr_base.icmpv6_type == byte(Icmpv6Type.echo_request) ||
       hdr_base.icmpv6_type == byte(Icmpv6Type.echo_reply) {
        hdr := Icmpv6HdrEcho {
            Icmpv6HdrBase: hdr_base
            id: be16(buf[4..6])
            seq_num: be16(buf[6..8])
        }

        return Icmpv6Hdr {
            hdr: hdr
        }
    }
    return Icmpv6Hdr {
        hdr : hdr_base
    }
}

fn (ih Icmpv6HdrBase) to_string() string {
    mut s := "Type:$ih.icmpv6_type "
    s += "Code:$ih.code "
    s += "Checksum:0x${ih.chksum:04X}"

    return s
}

fn (ih &Icmpv6HdrNeighborSolicitation) to_string() string {
    mut s := ih.Icmpv6HdrBase.to_string() + " "
    s += "TargetAddress:${ih.target_address.to_string()} "
    if ih.option.option_type != 0 {
        s += "OptionType:${ih.option.option_type} "
        s += "Length:${ih.option.length} "
        s += "LinkAddr:${ih.option.link_addr.to_string()}"
    }

    return s
}

fn (ih &Icmpv6HdrNeighborAdvertisement) to_string() string {
    mut s := ih.Icmpv6HdrBase.to_string() + " "
    s += "TargetAddress:${ih.target_address.to_string()} "
    s += "FlagRouter:${ih.flag_router} "
    s += "FlagSolicited:${ih.flag_solicited} "
    s += "FlagOverride:${ih.flag_override} "
    if ih.option.option_type != 0 {
        s += "OptionType:${ih.option.option_type} "
        s += "Length:${ih.option.length} "
        s += "LinkAddr:${ih.option.link_addr.to_string()}"
    }

    return s
}

fn (ih &Icmpv6HdrEcho) to_string() string {
    mut s := ih.Icmpv6HdrBase.to_string() + " "
    s += "ID:0x${ih.id:04X} "
    s += "SeqNum:0x${ih.seq_num:04X}"

    return s
}

fn (ih Icmpv6Hdr) to_string() string {
    hdr := ih.hdr
    match hdr {
        Icmpv6HdrBase {
            return hdr.to_string()
        }
        Icmpv6HdrNeighborSolicitation {
            return hdr.to_string()
        }
        Icmpv6HdrNeighborAdvertisement {
            return hdr.to_string()
        }
        else { return "" }
    }
}

fn (ih &Icmpv6HdrBase) to_bytes() []byte {
    mut buf := []byte{len: 4}
    buf[0] = ih.icmpv6_type
    buf[1] = ih.code
    copy(buf[2..4], be_u16_to_bytes(ih.chksum))

    return buf
}

fn (ih &Icmpv6HdrNeighborSolicitation) to_bytes() []byte {
    mut buf_base := ih.Icmpv6HdrBase.to_bytes()
    mut buf := []byte{len: 28}
    buf[0] = 0
    buf[1] = 0
    buf[2] = 0
    buf[3] = 0
    copy(buf[4..20], ih.target_address.addr[0..])
    if ih.option.option_type != 0 {
        buf[20] = ih.option.option_type
        buf[21] = byte(ih.option.length / 8)
        copy(buf[22..28], ih.option.link_addr.addr[0..])
        buf_base << buf
        return buf_base
    } else {
        buf_base << buf[0..20]
        return buf_base
    }
}

fn (ih &Icmpv6HdrNeighborAdvertisement) to_bytes() []byte {
    mut buf_base := ih.Icmpv6HdrBase.to_bytes()
    mut buf := []byte{len: 28}
    buf[0] = (byte(ih.flag_router) << 7) | (byte(ih.flag_solicited) << 6) | (byte(ih.flag_override) << 5)
    buf[1] = 0
    buf[2] = 0
    buf[3] = 0
    copy(buf[4..20], ih.target_address.addr[0..])
    if ih.option.option_type != 0 {
        buf[20] = ih.option.option_type
        buf[21] = byte(ih.option.length / 8)
        copy(buf[22..28], ih.option.link_addr.addr[0..])
        buf_base << buf
        return buf_base
    } else {
        buf_base << buf[0..20]
        return buf_base
    }
}

fn (ih &Icmpv6HdrEcho) to_bytes() []byte {
    mut buf_base := ih.Icmpv6HdrBase.to_bytes()
    mut buf := []byte{len: 4}
    copy(buf[0..2], be_u16_to_bytes(ih.id))
    copy(buf[2..4], be_u16_to_bytes(ih.seq_num))

    buf_base << buf
    return buf_base
}

fn (ih &Icmpv6Hdr) to_bytes() []byte {
    hdr := ih.hdr
    match hdr {
        Icmpv6HdrNeighborSolicitation {
            return hdr.to_bytes()
        }
        Icmpv6HdrNeighborAdvertisement {
            return hdr.to_bytes()
        }
        Icmpv6HdrEcho {
            return hdr.to_bytes()
        }
        else { return []byte{} }
    }
}

fn (mut ih Icmpv6Hdr) set_checksum(chksum u16) {
    match mut ih.hdr {
        Icmpv6HdrNeighborSolicitation {
            ih.hdr.chksum = chksum
        }
        Icmpv6HdrNeighborAdvertisement {
            ih.hdr.chksum = chksum
        }
        Icmpv6HdrEcho {
            ih.hdr.chksum = chksum
        }
        else {}
    }
}

struct Icmpv6HandleChans {
    recv_chan chan Packet
}

fn new_icmpv6_handle_chans() Icmpv6HandleChans {
    return Icmpv6HandleChans {
        recv_chan: chan Packet{cap: 10}
    }
}
fn (nd NetDevice) icmpv6_handle_thread(chans Icmpv6HandleChans) {
    for true {
        select {
            pkt := <- chans.recv_chan {
                icmpv6_hdr := pkt.l4_hdr.get_icmpv6_hdr() or {continue}
                hdr := icmpv6_hdr.hdr
                match hdr {
                    Icmpv6HdrNeighborSolicitation {
                        nd.handle_icmpv6_ns(pkt, &hdr)
                    }
                    Icmpv6HdrEcho {
                        if hdr.icmpv6_type == byte(Icmpv6Type.echo_request) {
                            nd.handle_icmpv6_echo(pkt, &hdr)
                        }
                    }
                    else {}
                }
            }
        }
    }
}