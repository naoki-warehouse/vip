module main

fn test_arp_table_insert_and_get() {
	shared arp_table := new_arp_table()
	arp_col := ArpTableCol{
		mac: parse_physical_address("01:23:45:67:89:AB") or { panic(err) }
		ip: parse_ip_address("192.168.10.2") or { panic(err) }
	}
	arp_table.insert(arp_col)

	res := arp_table.get(arp_col.ip) or { panic(err) }
	assert res.ip.str() == "192.168.10.2"
	assert res.mac.str() == "01:23:45:67:89:AB"

	arp_table.delete(arp_col.ip)
	arp_table.get(arp_col.ip) or { return }
	panic("delete")
}
