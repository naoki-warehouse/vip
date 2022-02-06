module main

struct Socket {
	my_physical_addr PhysicalAddress
	my_ip_addr IpAddress
	netdevice_chan NetDeviceChannel
mut:
	arp_table shared ArpTable
}

fn new_socket(netdev &NetDevice, netdevice_chan NetDeviceChannel, shared arp_table ArpTable) Socket {
	return Socket {
		my_physical_addr: netdev.physical_addr
		my_ip_addr: netdev.ip_addr
		netdevice_chan: netdevice_chan
		arp_table: arp_table
	}
}
