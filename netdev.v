module main

import os

struct NetDevice {
	tap_name string
	tap_recv_chan chan []byte
	physical_addr PhysicalAddress
	ip_addr IpAddress
	arp_chan NetDeviceChannel
	icmp_chan NetDeviceChannel
	send_chan chan &Packet
mut:
	socket_chans map[string]NetDeviceChannel
	arp_table shared ArpTable
	tap_fd os.File
}

struct NetDeviceChannel {
	recv_chan chan &Packet
	send_chan chan &Packet
}

fn new_netdevice() ?NetDevice {
	send_chan := chan &Packet{cap: 10}
	return NetDevice {
		tap_name: "vip-test"
		tap_recv_chan: chan []byte{cap: 10}
		physical_addr: parse_physical_address("52:54:00:4D:3F:E4")?
		ip_addr: parse_ip_address("192.168.10.2")?
		arp_chan: new_netdevice_channel(send_chan)
		icmp_chan: new_netdevice_channel(send_chan)
		send_chan: send_chan
		socket_chans: map[string]NetDeviceChannel{}
		arp_table: new_arp_table()
	}
}

fn new_netdevice_channel(send_chan chan &Packet) NetDeviceChannel {
	return NetDeviceChannel{
		recv_chan: chan &Packet{cap: 10}
		send_chan: send_chan
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
