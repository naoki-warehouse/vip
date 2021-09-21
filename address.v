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

struct IPv4Address {
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

struct AddrInfo {
mut:
    mac PhysicalAddress
    ipv4 IPv4Address
    port u16
}