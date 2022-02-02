module main

import net.conv

type L2Hdr = EthHdr | HdrNone
type L3Hdr = ArpHdr | HdrNone

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
	}
}

struct Packet {
mut:
	l2_hdr &L2Hdr
	l3_hdr &L3Hdr
}

fn new_packet() Packet {
	return Packet {
		l2_hdr: &HdrNone{}
		l3_hdr: &HdrNone{}
	}
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
				println("IPV4")
				return 0
			} else if ether_type == 0x86DD {
				println("IPV6")
				return 0
			} else {
				return error('unknown ether_type 0x${ether_type:04X}')
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

fn (pkt &Packet) str() string {
	return pkt.str_l2() + "\n" +  pkt.str_l3()
}

fn (pkt &Packet) write_bytes(mut buf []byte) ?int {
	mut offset := 0
	assert buf.len >= pkt.l2_hdr.len()
	offset += pkt.l2_hdr.write_bytes(mut buf[offset..])?
	assert buf.len >= offset + pkt.l3_hdr.len()
	offset += pkt.l3_hdr.write_bytes(mut buf[offset..])?
	return offset
}
