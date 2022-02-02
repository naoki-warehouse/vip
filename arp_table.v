module main

import time

struct ArpTableCol {
mut:
    mac PhysicalAddress
    ip  IpAddress
    ttl time.Time
}


struct ArpTable {
mut:
    table map[string]ArpTableCol
}

fn new_arp_table() ArpTable {
	return ArpTable {
		table: map[string]ArpTableCol
	}
}

fn (shared at ArpTable) insert (col ArpTableCol) {
	lock at {
		at.table[col.ip.str()] = col
		at.table[col.ip.str()].ttl = time.now().add_seconds(30)
	}
}

fn (shared at ArpTable) delete (ip IpAddress) {
	lock at {
 		at.table.delete(ip.str())
	}
}

fn (shared at ArpTable) get(ip IpAddress) ?ArpTableCol {
	return rlock at {
 		at.table[ip.str()]?
	}
}

fn (shared at ArpTable) print() {
	rlock at {
		for _, atc in at.table {
			println("${atc.mac} ${atc.ip}")
		}
	}
}