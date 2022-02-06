module main

import net.conv

type L2Hdr = HdrNone | EthHdr
type L3Hdr = HdrNone | ArpHdr | IpHdr
type L4Hdr = HdrNone | IcmpHdr | UdpHdr

struct HdrNone {}

fn (hdr &HdrNone) str() string {
	return "None"
}

fn (hdr &L2Hdr) len() int {
	match hdr {
		HdrNone {
			return 0
		}
		EthHdr {
			return hdr.len()
		}
	}
}

fn (hdr &L2Hdr) write_bytes(mut buf []byte) ?int {
	match hdr {
		HdrNone {
			return 0
		}
		EthHdr {
			return hdr.write_bytes(mut buf)
		}
	}
}

fn (hdr &L3Hdr) len() int {
	match hdr {
		HdrNone {
			return 0
		}
		ArpHdr {
			return hdr.len()
		}
		IpHdr {
			return hdr.len()
		}
	}
}

fn (hdr &L3Hdr) write_bytes(mut buf []byte) ?int {
	match hdr {
		HdrNone {
			return 0
		}
		ArpHdr {
			return hdr.write_bytes(mut buf)
		}
		IpHdr {
			return hdr.write_bytes(mut buf)
		}
	}
}

fn (hdr &L4Hdr) len() int {
	match hdr {
		HdrNone {
			return 0
		}
		IcmpHdr {
			return hdr.len()
		}
		UdpHdr {
			return hdr.len()
		}
	}
}

fn (hdr &L4Hdr) write_bytes(mut buf []byte) ?int {
	match hdr {
		HdrNone {
			return 0	
		}
		IcmpHdr {
			return hdr.write_bytes(mut buf)
		}
		UdpHdr {
			return hdr.write_bytes(mut buf)
		}
	}
}

struct Packet {
mut:
	l2_hdr &L2Hdr
	l3_hdr &L3Hdr
	l4_hdr &L4Hdr
	payload []byte
}

fn new_packet() Packet {
	return Packet {
		l2_hdr: &HdrNone{}
		l3_hdr: &HdrNone{}
		l4_hdr: &HdrNone{}
	}
}

fn parse_packet(buf []byte) ?Packet {
	mut pkt := new_packet()
    mut offset := 0
    offset += pkt.parse_l2_header(buf[offset..])?
    offset += pkt.parse_l3_header(buf[offset..])?
    offset += pkt.parse_l4_header(buf[offset..])?
	pkt.payload = buf[offset..]
	return pkt
}

fn (mut pkt Packet) parse_l2_header(buf []byte) ?int {
	eth_hdr := parse_ethernet_header(buf)?
	pkt.l2_hdr = eth_hdr
	return eth_hdr.len()
}

fn (mut pkt Packet) parse_l3_header(buf []byte) ?int {
	l2_hdr := pkt.l2_hdr
	match l2_hdr {
		HdrNone {
			return error("l2_hdr is not set")
		}
		EthHdr {
			ether_type := conv.nth16(l2_hdr.ether_type)
			if ether_type == 0x0806 {
				pkt.l3_hdr = parse_arp_header(buf)?
				return int(sizeof(ArpHdr))
			} else if ether_type == 0x0800 {
				ip_hdr := parse_ip_header(buf)?
				pkt.l3_hdr = ip_hdr
				return ip_hdr.len()
			} else if ether_type == 0x86DD {
				println("IPV6")
				return 0
			} else {
				return error('unknown ether_type 0x${ether_type:04X}')
			}
		}
	}
}

fn (mut pkt Packet) parse_l4_header(buf []byte) ?int {
	l3_hdr := pkt.l3_hdr
	match l3_hdr {
		HdrNone {
			return 0
		}
		ArpHdr {
			return 0
		}
		IpHdr {
			protocol := l3_hdr.base.protocol
			if protocol == 1 {
				icmp_hdr := parse_icmp_header(buf)?
				pkt.l4_hdr = icmp_hdr
				return icmp_hdr.len()
			} else if protocol == 17 {
				udp_hdr := parse_udp_header(buf)?
				pkt.l4_hdr = udp_hdr
				return udp_hdr.len()
			} else {
				return error("unknown ip protocol ${protocol}")
			}
		}
	}
}

fn (pkt &Packet) str_l2() string {
	return pkt.l2_hdr.str()
}

fn (pkt &Packet) str_l3() string {
	return pkt.l3_hdr.str()
}

fn (pkt &Packet) str_l4() string {
	return pkt.l4_hdr.str()
}

fn (pkt &Packet) str() string {
	return pkt.str_l2() + "\n" +  pkt.str_l3() + "\n" + pkt.str_l4()
}

fn (pkt &Packet) write_bytes(mut buf []byte) ?int {
	mut offset := 0
	assert buf.len >= pkt.l2_hdr.len()
	offset += pkt.l2_hdr.write_bytes(mut buf[offset..])?
	assert buf.len >= offset + pkt.l3_hdr.len()
	offset += pkt.l3_hdr.write_bytes(mut buf[offset..])?
	assert buf.len >= offset + pkt.l4_hdr.len()
	l4_hdr_offset := offset
	offset += pkt.l4_hdr.write_bytes(mut buf[offset..])?
	offset += copy(buf[offset..], pkt.payload)

	match pkt.l4_hdr {
		HdrNone {

		}
		IcmpHdr {
			chksum := calc_chksum(buf[l4_hdr_offset..offset])
			copy(buf[l4_hdr_offset+2..], be_u16_to_bytes(chksum))
		}
		UdpHdr {
			chksum := calc_chksum(buf[l4_hdr_offset..offset])
			copy(buf[l4_hdr_offset+6..], be_u16_to_bytes(chksum))
		}
	}
	return offset
}
