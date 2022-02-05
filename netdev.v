module main

import os
import net.conv

struct NetDevice {
	tap_name string
	tap_recv_chan chan []byte
	physical_addr PhysicalAddress
	ip_addr IpAddress
mut:
	arp_table shared ArpTable
	tap_fd os.File
}

fn new_netdevice() ?NetDevice {
	return NetDevice {
		tap_name: "vip-test"
		tap_recv_chan: chan []byte{cap: 10}
		physical_addr: parse_physical_address("52:54:00:4D:3F:E4")?
		ip_addr: parse_ip_address("192.168.10.2")?
		arp_table: new_arp_table()
	}
}

fn (mut nd NetDevice) create_tap()? {
	nd.tap_fd = tap_alloc(nd.tap_name)?
}

fn (nd NetDevice) str() string {
	mut s := ""
	s += "TAPDeviceName:   ${nd.tap_name}\n"
	s += "PhysicalAddress: ${nd.physical_addr}\n"
	s += "IpAddress:       ${nd.ip_addr}"

	return s
}

fn (mut nd NetDevice) send_packet(pkt &Packet)? {
	mut buf := []byte{len:9000}
	send_size := pkt.write_bytes(mut buf)?
	C.write(nd.tap_fd.fd, buf.data, send_size)
}

fn (mut nd NetDevice) send_ethernet(mut pkt Packet, dst_addr &SocketAddress)? {
	mut l2_hdr := &EthHdr {
		dmac: dst_addr.physical_addr
		smac: nd.physical_addr
	}

	l3_hdr := pkt.l3_hdr
	match l3_hdr {
		HdrNone {
			panic("l3_hdr is not set")
		}
		ArpHdr {
			l2_hdr.ether_type = conv.htn16(0x0806)
		}
		IpHdr {
			l2_hdr.ether_type = conv.htn16(0x0800)
		}
	}
	pkt.l2_hdr = l2_hdr

	return nd.send_packet(pkt)
}

fn (mut nd NetDevice) send_ip(mut pkt Packet, dst_addr &SocketAddress)? {
	mut ip_hdr_base := &IpHdrBase {
		vh: (4 << 4) | (5)
		tos: 0
		total_len: conv.htn16(u16(20 + pkt.l4_hdr.len() + pkt.payload.len))
		id: 0x1234
		fragment: 0
		ttl: 64
		protocol: 0
		chksum: 0
		src_addr: nd.ip_addr
		dst_addr: dst_addr.ip_addr
	}

	l4_hdr := pkt.l4_hdr
	match l4_hdr {
		HdrNone {
			panic("l4_hdr is not set")
		}
		IcmpHdr {
			ip_hdr_base.protocol = 1
		}
	}

	pkt.l3_hdr = &IpHdr {
		base: ip_hdr_base
	}

	return nd.send_ethernet(mut pkt, dst_addr)
}

fn (mut nd NetDevice) handle_arp_reply(ap &ArpHdr) {
	nd.arp_table.insert(ArpTableCol{mac: ap.sha, ip: ap.spa})
}

fn (mut nd NetDevice) handle_arp_request (ap &ArpHdr, sock_addr &SocketAddress) {
	nd.arp_table.insert(ArpTableCol{mac: ap.sha, ip: ap.spa})


	mut res_pkt := Packet {
		l2_hdr: &HdrNone {}
		l3_hdr: &ArpHdr {
			hw_type: conv.htn16(u16(ArpHWType.ethernet)),
			proto_type: conv.htn16(u16(ArpProtoType.ipv4)),
			hw_size: 6,
			proto_size: 4,
			op: conv.htn16(u16(ArpOpcode.reply)),
			sha: nd.physical_addr,
			spa: nd.ip_addr,
			tha: ap.sha,
			tpa: ap.spa,
		}
		l4_hdr: &HdrNone{}
		payload: []byte{}
	}

	nd.send_ethernet(mut res_pkt, sock_addr) or {panic(err)}
}

fn (mut nd NetDevice) handle_arp (pkt &Packet, ap &ArpHdr, sock_addr &SocketAddress) {
	op := conv.nth16(ap.op)
	if op == u16(ArpOpcode.request) {
		nd.handle_arp_request(ap, sock_addr)
	} else if op == u16(ArpOpcode.reply) {
		nd.handle_arp_reply(ap)
	}
}

fn (mut nd NetDevice) handle_ip(pkt &Packet, ip &IpHdr, mut sock_addr SocketAddress) {
	l4_hdr := pkt.l4_hdr
	match l4_hdr {
		HdrNone {

		}
		IcmpHdr {
			nd.handle_icmp(pkt, l4_hdr, mut sock_addr)
		}
	}
}

fn (mut nd NetDevice) handle_icmp(pkt &Packet, icmp &IcmpHdr, mut sock_addr SocketAddress) {
	icmp_typ := icmp.typ
	match icmp_typ {
		IcmpHdrUnknown {}
		IcmpHdrEcho {
			nd.handle_icmp_echo(pkt, icmp_typ, sock_addr)
		}
	}
}

fn (mut nd NetDevice) handle_icmp_echo(pkt &Packet, icmp &IcmpHdrEcho, sock_addr &SocketAddress) {
	println("$icmp")
	mut s := "payload: ["
	for i := 0; i < pkt.payload.len; i += 1 {
		s += "0x${pkt.payload[i]:02X} "
	}
	s += "]"
	println(s)

	mut res_pkt := Packet {
		l2_hdr: &HdrNone {}
		l3_hdr: &HdrNone {}
		l4_hdr: &IcmpHdr {
			base: &IcmpHdrBase {
				icmp_type: u8(IcmpType.echo_reply)
				code: 0
				chksum: 0
			}
			typ: &IcmpHdrEcho {
				id: icmp.id
				seq_num: icmp.seq_num
			}
		}
		payload: pkt.payload
	}

	nd.send_ip(mut res_pkt, sock_addr) or {panic(err)}
}

fn (mut nd NetDevice) handle_pkt(pkt &Packet) {
	mut sock_addr := SocketAddress{}
	l2_hdr := pkt.l2_hdr
	match l2_hdr {
		HdrNone {
			return
		}
		EthHdr {
			sock_addr.physical_addr = l2_hdr.smac
		}
	}

    l3_hdr := pkt.l3_hdr
    match l3_hdr {
        HdrNone {
        }
        ArpHdr {
            nd.handle_arp(pkt, l3_hdr, sock_addr)
        }
		IpHdr {
			sock_addr.ip_addr = l3_hdr.base.src_addr
			nd.handle_ip(pkt, l3_hdr, mut sock_addr)
		}
    }
}