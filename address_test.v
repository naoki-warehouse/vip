module main

fn test_parse_physical_address() {
	mac_str := "01:23:45:67:89:AB"
	mac := parse_physical_address(mac_str) or { panic(err) }
	assert mac.addr[0] == 0x01
	assert mac.addr[1] == 0x23
	assert mac.addr[2] == 0x45
	assert mac.addr[3] == 0x67
	assert mac.addr[4] == 0x89
	assert mac.addr[5] == 0xAB
	assert mac_str == mac.str()
}

fn test_parse_ip_address() {
	ip_str := "192.168.10.1"
	ip := parse_ip_address(ip_str) or { panic(err) }
	assert ip.addr[0] == 192
	assert ip.addr[1] == 168
	assert ip.addr[2] == 10
	assert ip.addr[3] == 1
	assert ip_str == ip.str()
}