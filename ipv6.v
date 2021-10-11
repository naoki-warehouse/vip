module main

import time

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
    tcp = 6
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
    if hdr.next_header == byte(IPv6Protocol.tcp) {
        hdr.protocol = IPv6Protocol.tcp
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

struct NeighborTable {
    my_mac PhysicalAddress
    my_ipv6 IPv6Address
mut:
    table map[string]NeighborTableCol
}

struct NeighborTableCol {
mut:
    mac PhysicalAddress
    ip6 IPv6Address
    ttl time.Time
}

fn (ntc &NeighborTableCol) to_string() string {
    ttl_sec := ntc.ttl.unix_time() - time.now().unix_time()
    return "MACAddresss:${ntc.mac.to_string()} IPv6Address:${ntc.ip6.to_string()} " +
           "TTL: ${ttl_sec}sec"
}

struct NeighborTableChans {
    insert_chan chan NeighborTableCol
    get_chan chan NeighborTableCol
}

fn new_neighbor_table_chans() NeighborTableChans {
    return NeighborTableChans {
        insert_chan : chan NeighborTableCol{}
        get_chan : chan NeighborTableCol{}
    }
}

fn new_neighbor_table() &NeighborTable {
    return &NeighborTable {
        table: map[string]NeighborTableCol{}
    }
}

fn (mut nt NeighborTable) insert(col NeighborTableCol) {
    nt.table[col.ip6.to_string()] = col
    nt.table[col.ip6.to_string()].ttl = time.now().add_seconds(30)
}

fn (mut nt NeighborTable) get(ip6 IPv6Address) ?NeighborTableCol {
    return nt.table[ip6.to_string()]
}

fn (chans NeighborTableChans) neighbor_table_thread(my_mac &PhysicalAddress, my_ipv6 &IPv6Address) {
    mut neighbor_table := NeighborTable {
        my_mac: *my_mac
        my_ipv6: *my_ipv6
    }

    for true {
        select {
            col := <- chans.insert_chan {
                neighbor_table.insert(col)
                println("[Neighbor Table] Inserted ${col.to_string()}")
            }
            col := <- chans.get_chan {
                res := neighbor_table.get(col.ip6) or { NeighborTableCol{} }
                println("[Neighbor Table] Get ${res.to_string()}")
                chans.get_chan <- res
            }
        }
    }
}