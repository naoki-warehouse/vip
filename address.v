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

struct AddrInfo {
mut:
    mac PhysicalAddress
    ipv4 IPv4Address
    port u16
}


type SockAddrType = SockAddrBase | SockAddrIn
struct SockAddr {
    addr SockAddrType
}

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

fn parse_sockaddr(buf []byte) ?SockAddr {
    assert buf.len >= 16

    family := buf[0] | buf[1] << 8
    if family == C.AF_INET {
        return SockAddr {
            addr : SockAddrIn {
                family : family
                sin_port : buf[2] << 8 | buf[3]
                sin_addr : parse_ipv4_address(buf[4..8])
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
        SockAddrBase {
            return "$addr.addr"
        }
        SockAddrIn {
            return  addr.addr.to_string()
        }
    }
}

fn (addr SockAddrIn) to_string() string {
    mut s := "family:AF_INET "
    s += "sin_port:${addr.sin_port} "
    s += "sin_addr:${addr.sin_addr.to_string()}"
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