module main

import strconv

[packed]
struct PhysicalAddress {
	addr [6]byte
}

[packed]
struct IpAddress {
    addr [4]byte
}

struct SocketAddress {
mut:
	physical_addr PhysicalAddress
	ip_addr IpAddress
	port u16
}

fn new_physical_address_from_buf(buf [6]byte) ?PhysicalAddress {
	return PhysicalAddress {
		addr: buf
	}
}

fn parse_physical_address(addr string) ?PhysicalAddress {
	addrs := addr.split(":")
	assert addrs.len == 6
	mut buf := [6]byte{}
	for i := 0; i < 6; i += 1 {
		buf[i] = byte(strconv.parse_int(addrs[i], 16, 16)? & 0xFF)
	}

	return PhysicalAddress {
		addr: buf
	}
}

fn (pa PhysicalAddress) str() string {
	mut s := ""
	for a in pa.addr {
		s += ":${a:02X}"
	}

	return s[1..]
}

fn parse_ip_address(addr string) ?IpAddress {
	addrs := addr.split(".")
	assert addrs.len == 4
	mut buf := [4]byte{}
	for i := 0; i < 4; i += 1 {
		buf[i] = byte(strconv.parse_int(addrs[i], 10, 16)? & 0xFF)
	}

	return IpAddress {
		addr: buf
	}
}

fn (ia IpAddress) str() string {
    mut s := ""
    for a in ia.addr {
        s += ".$a"
    }

    return s[1..]
}
