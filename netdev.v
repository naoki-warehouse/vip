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