module main

struct PhysicalAddress {
mut:
    addr [6]byte
}

fn parse_physical_address(buf []byte) PhysicalAddress {
    assert buf.len == 6

    mut phy_addr := PhysicalAddress{}
    for i := 0; i < 6; i += 1 {
        phy_addr.addr[i] = buf[i]
    }

    return phy_addr
}

fn (pa PhysicalAddress) to_string() string {
    mut s := ""
    for a in pa.addr {
        s += ":${a:02X}"
    }
    
    return s[1..]
}

fn (pa PhysicalAddress) == (pb PhysicalAddress) bool {
    for i := 0; i < 6; i++ {
        if pa.addr[i] != pb.addr[i] {
            return false
        }
    }

    return true
}

fn physical_address_bcast() PhysicalAddress {
    mut phy_addr := PhysicalAddress{}
    for i := 0; i < 6; i += 1 {
        phy_addr.addr[i] = 0xFF
    }

    return phy_addr
}

struct IPv4Address {
    subnet_length int
mut:
    addr [4]byte
}

fn parse_ipv4_address(buf []byte) IPv4Address {
    assert buf.len == 4
    mut ipv4_addr := IPv4Address{}

    for i := 0; i < 4; i += 1 {
        ipv4_addr.addr[i] = buf[i]
    }

    return ipv4_addr
}

fn (ia IPv4Address) to_string() string {
    mut s := ""
    for a in ia.addr {
        s += ".$a"
    }

    return s[1..]
}

fn (ia IPv4Address) == (ib IPv4Address) bool {
    for i := 0; i < 4; i += 1 {
        if ia.addr[i] != ib.addr[i] {
            return false
        }
    }

    return true
}

fn (ia &IPv4Address) contains(addr &IPv4Address) bool {
    mut network_mask := u32(0)
    for i := 0; i < 32; i += 1 {
        network_mask = network_mask << 1
        if i < ia.subnet_length {
            network_mask |= 1
        }
    }
    ip_a := be_bytes_to_u32(ia.addr[0..4]) or {return false}
    ip_b := be_bytes_to_u32(addr.addr[0..4]) or {return false}
    return (ip_a ^ ip_b) & network_mask == 0
}

struct IPv6Address {
    subnet_length int
mut:
    addr [16]byte
}

fn parse_ipv6_address(buf []byte) IPv6Address {
    assert buf.len >= 16
    mut ipv6_addr := IPv6Address{}

    for i := 0; i < 16; i += 1 {
        ipv6_addr.addr[i] = buf[i]
    }

    return ipv6_addr
}

fn (ia &IPv6Address) to_string() string {
    mut s := ""
    for i := 0; i < 16; i += 1 {
        if i != 0 && i % 2 == 0 {
            s += ":"
        }
        s += "${ia.addr[i]:02x}"
    }

    return s
}

fn (ia IPv6Address) == (ib IPv6Address) bool {
    for i := 0; i < 16; i += 1 {
        if ia.addr[i] != ib.addr[i] {
            return false
        }
    }

    return true
}

fn (ia &IPv6Address) get_ns_mac_addr() PhysicalAddress {
    mut addr := PhysicalAddress{}
    addr.addr[0] = 0x33
    addr.addr[1] = 0x33
    addr.addr[2] = 0xFF
    addr.addr[3] = ia.addr[13]
    addr.addr[4] = ia.addr[14]
    addr.addr[5] = ia.addr[15]

    return addr
}

fn (ia &IPv6Address) get_ns_multicast_addr() IPv6Address {
    mut addr := IPv6Address{}
    addr.addr[0] = 0xFF
    addr.addr[1] = 0x02
    addr.addr[11] = 0x01
    addr.addr[12] = 0xFF
    addr.addr[13] = ia.addr[13]
    addr.addr[14] = ia.addr[14]
    addr.addr[15] = ia.addr[15]

    return addr
}

fn (ia &IPv6Address) is_link_local_address() bool {
    return ia.addr[0] == 0xFE && ia.addr[1] == 0x80
}

struct AddrInfo {
mut:
    mac PhysicalAddress
    ipv4 IPv4Address
    ipv6 IPv6Address
    port u16
}


type SockAddrType = SockAddrNone | SockAddrBase | SockAddrIn | SockAddrIn6
struct SockAddr {
    addr SockAddrType
}

struct SockAddrNone {}

struct SockAddrBase {
mut:
    family u16
    data []byte
}

struct SockAddrIn {
    len int = 16
mut:
    family u16 = u16(C.AF_INET)
    sin_port u16
    sin_addr IPv4Address 
}

struct SockAddrIn6 {
    len int = 28
mut:
    sin6_family u16 = u16(C.AF_INET6)
    sin6_port u16
    sin6_flowinfo u32
    sin6_addr IPv6Address
    sin6_scope_id u32
}

fn parse_sockaddr(buf []byte) ?SockAddr {
    if buf.len == 0 {
        return SockAddr {
            addr: SockAddrNone{}
        }
    }

    family := buf[0] | buf[1] << 8
    if family == C.AF_INET {
        assert buf.len >= 16
        return SockAddr {
            addr : SockAddrIn {
                family : family
                sin_port : buf[2] << 8 | buf[3]
                sin_addr : parse_ipv4_address(buf[4..8])
            }
        }
    }

    if family == C.AF_INET6 {
        assert buf.len >= 28
        return SockAddr {
            addr : SockAddrIn6 {
                sin6_family : family
                sin6_port : be16(buf[2..4])
                sin6_flowinfo : be_bytes_to_u32(buf[4..8]) ?
                sin6_addr : parse_ipv6_address(buf[8..24])
                sin6_scope_id : be_bytes_to_u32(buf[24..28]) ?
            }
        }
    }

    return SockAddr {
        addr : SockAddrBase {
            family : family
            data : buf[2..16]
        }
    }
}

fn (addr SockAddr) to_string() string {
    match addr.addr {
        SockAddrNone {
            return "None"
        }
        SockAddrBase {
            return "$addr.addr"
        }
        SockAddrIn {
            return  addr.addr.to_string()
        }
        SockAddrIn6 {
            return addr.addr.to_string()
        }
    }
}

fn (addr SockAddrIn) to_string() string {
    mut s := "family:AF_INET "
    s += "sin_port:${addr.sin_port} "
    s += "sin_addr:${addr.sin_addr.to_string()}"
    return s
}

fn (addr SockAddrIn6) to_string() string {
    mut s := "family:AF_INET6 "
    s += "sin6_port:${addr.sin6_port} "
    s += "sin6_flowinfo:0x${addr.sin6_flowinfo:08X} "
    s += "sin6_addr:${addr.sin6_addr.to_string()} "
    s += "sin6_scope_id:0x${addr.sin6_scope_id:08X}"
    return s
}

fn (addr SockAddrIn) to_bytes() []byte {
    mut buf := []byte{len: addr.len}
    buf[0] = byte(addr.family)
    buf[1] = byte(addr.family >> 8)
    buf[2] = byte(addr.sin_port)
    buf[3] = byte(addr.sin_port >> 8)
    for i := 0; i < 4; i += 1 {
        buf[4+i] = addr.sin_addr.addr[i]
    }

    return buf
}

fn (addr SockAddrIn6) to_bytes() []byte {
    mut buf := []byte{len: addr.len}
    copy(buf[0..2], u16_to_bytes(addr.sin6_family))
    copy(buf[2..4], u16_to_bytes(addr.sin6_port))
    copy(buf[4..8], u32_to_bytes(addr.sin6_flowinfo))
    copy(buf[8..24], addr.sin6_addr.addr[0..])
    copy(buf[24..28], u32_to_bytes(addr.sin6_scope_id))

    return buf
}
