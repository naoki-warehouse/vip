module main

import net.conv

[packed]
struct ArpHdr {
	hw_type    u16
	proto_type u16
	hw_size    u8
	proto_size u8
	op         u16
	sha        PhysicalAddress
	spa        IpAddress
	tha        PhysicalAddress
	tpa        IpAddress
}

enum ArpHWType {
	ethernet = 0x0001
}

enum ArpProtoType {
	ipv4 = 0x0800
}

enum ArpOpcode {
	request = 0x0001
	reply = 0x0002
}

fn parse_arp_header(buf []byte) ?&ArpHdr {
	assert buf.len >= sizeof(ArpHdr)

	return unsafe { &ArpHdr(&buf[0]) }
}

fn (ap &ArpHdr) len() int {
	return int(sizeof(ArpHdr))
}

fn (ap &ArpHdr) str() string {
	mut s := 'hw_type:'
	hw_type := conv.nth16(ap.hw_type)
	if hw_type == u16(ArpHWType.ethernet) {
		s += 'Ethernet '
	} else {
		s += '0x$hw_type '
	}

	proto_type := conv.nth16(ap.proto_type)
	s += 'proto_type:'
	if proto_type == u16(ArpProtoType.ipv4) {
		s += 'IPv4 '
	} else {
		s += '0x$proto_type '
	}

	op := conv.nth16(ap.op)
	s += 'op:'
	if op == u16(ArpOpcode.request) {
		s += 'Request '
	} else if op == u16(ArpOpcode.reply) {
		s += 'Reply '
	}

	s += 'sha:$ap.sha '
	s += 'spa:$ap.spa '
	s += 'tha:$ap.tha '
	s += 'tpa:$ap.tpa'

	return s
}

fn (ap &ArpHdr) write_bytes(mut buf []byte) ?int {
	assert buf.len >= ap.len()
	mut offset := 0
	offset += copy(buf[offset..], le_u16_to_bytes(ap.hw_type))
	offset += copy(buf[offset..], le_u16_to_bytes(ap.proto_type))
	buf[offset] = ap.hw_size
	offset += 1
	buf[offset] = ap.proto_size
	offset += 1
	offset += copy(buf[offset..], le_u16_to_bytes(ap.op))
	offset += copy(buf[offset..], ap.sha.addr[0..])
	offset += copy(buf[offset..], ap.spa.addr[0..])
	offset += copy(buf[offset..], ap.tha.addr[0..])
	offset += copy(buf[offset..], ap.tpa.addr[0..])

	return offset
}

struct ArpHandler {
	Socket
}

fn new_arp_handler(nd &NetDevice) ArpHandler {
	shared at := nd.arp_table
	return ArpHandler{new_socket(nd, nd.arp_chan, shared at)}
}

fn (mut sock ArpHandler) handle_arp_reply(ap &ArpHdr) {
	sock.arp_table.insert(ArpTableCol{ mac: ap.sha, ip: ap.spa })
}

fn (mut sock ArpHandler) handle_arp_request(ap &ArpHdr, sock_addr &SocketAddress) {
	sock.arp_table.insert(ArpTableCol{ mac: ap.sha, ip: ap.spa })

	res_pkt := sock.create_arp_reply(sock_addr) or { panic(err) }
	sock.netdevice_chan.send_chan <- &res_pkt
}

fn (sock &Socket) create_arp_reply(dst_addr &SocketAddress) ?Packet {
	mut res_pkt := Packet{
		l2_hdr: &HdrNone{}
		l3_hdr: &ArpHdr{
			hw_type: conv.htn16(u16(ArpHWType.ethernet))
			proto_type: conv.htn16(u16(ArpProtoType.ipv4))
			hw_size: 6
			proto_size: 4
			op: conv.htn16(u16(ArpOpcode.reply))
			sha: sock.my_physical_addr
			spa: sock.my_ip_addr
			tha: dst_addr.physical_addr
			tpa: dst_addr.ip_addr
		}
		l4_hdr: &HdrNone{}
		payload: []byte{}
	}

	sock.create_ethernet(mut res_pkt, dst_addr) ?
	return res_pkt
}

fn arp_handler(ah ArpHandler) {
	mut sock := ah
	for true {
		pkt := <-sock.netdevice_chan.recv_chan
		mut sock_addr := SocketAddress{}
		l2_hdr := pkt.l2_hdr
		match l2_hdr {
			HdrNone {
				continue
			}
			EthHdr {
				sock_addr.physical_addr = l2_hdr.smac
			}
		}
		l3_hdr := pkt.l3_hdr
		match l3_hdr {
			HdrNone {
				continue
			}
			IpHdr {
				continue
			}
			ArpHdr {
				ap := l3_hdr
				op := conv.nth16(ap.op)
				sock_addr.ip_addr = ap.spa
				if op == u16(ArpOpcode.request) {
					sock.handle_arp_request(ap, sock_addr)
				} else if op == u16(ArpOpcode.reply) {
					sock.handle_arp_reply(ap)
				}
			}
		}
	}
}
