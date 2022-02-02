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

fn (mut nd NetDevice) send_packet(pkt &Packet)? {
	mut buf := []byte{len:9000}
	send_size := pkt.write_bytes(mut buf)?
	C.write(nd.tap_fd.fd, buf.data, send_size)
}

fn (nd NetDevice) str() string {
	mut s := ""
	s += "TAPDeviceName:   ${nd.tap_name}\n"
	s += "PhysicalAddress: ${nd.physical_addr}\n"
	s += "IpAddress:       ${nd.ip_addr}"

	return s
}

fn (mut nd NetDevice) handle_arp_reply() {

}

fn (mut nd NetDevice) handle_arp_request (ap &ArpHdr) {
	nd.arp_table.insert(ArpTableCol{mac: ap.sha, ip: ap.spa})


	res_pkt := Packet {
		l2_hdr: &EthHdr {
			dmac: ap.sha,
			smac: nd.physical_addr,
			ether_type: conv.htn16(0x0806),
		},
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
	}

	nd.send_packet(&res_pkt) or {panic(err)}
}

fn (mut nd NetDevice) handle_arp (pkt &Packet, ap &ArpHdr) {
	if conv.nth16(ap.op) == u16(ArpOpcode.request) {
		nd.handle_arp_request(ap)
	}
}

fn (mut nd NetDevice) handle_pkt(pkt &Packet) {
    l3_hdr := pkt.l3_hdr
    match l3_hdr {
        HdrNone {
        }
        ArpHdr {
            nd.handle_arp(pkt, l3_hdr)
        }
    }
}