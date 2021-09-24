module main

import time

struct ArpHdr {
mut:
    hw_type u16
    proto_type u16
    hw_size u8
    proto_size u8
    op u16
    sha PhysicalAddress
    spa IPv4Address
    tha PhysicalAddress
    tpa IPv4Address
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

fn parse_arp_hdr(buf []byte) ?ArpHdr {
    assert buf.len >= sizeof(ArpHdr)

    mut arp_hdr := ArpHdr{
        hw_type : be16(buf[0..2])
        proto_type : be16(buf[2..4])
        hw_size : buf[4]
        proto_size: buf[5]
        op : be16(buf[6..8])
        sha : parse_physical_address(buf[8..14])
        spa : parse_ipv4_address(buf[14..18])
        tha: parse_physical_address(buf[18..24])
        tpa : parse_ipv4_address(buf[24..28])
    }

    return arp_hdr
}

fn (ah ArpHdr) to_bytes() []byte {
    mut buf := []byte{len:28}
    copy(buf[0..2], be_u16_to_bytes(ah.hw_type))
    copy(buf[2..4], be_u16_to_bytes(ah.proto_type))
    buf[4] = ah.hw_size
    buf[5] = ah.proto_size
    copy(buf[6..8], be_u16_to_bytes(ah.op))
    copy(buf[8..14], ah.sha.addr[0..6])
    copy(buf[14..18], ah.spa.addr[0..4])
    copy(buf[18..24], ah.tha.addr[0..6])
    copy(buf[24..28], ah.tpa.addr[0..4])

    return buf
}

fn (ah ArpHdr) to_string() string {
    mut s := ""
    s += "HWType: 0x${ah.hw_type:04X} "
    s += "ProtoType: 0x${ah.proto_type:04X} "
    s += "HWSize: $ah.hw_size "
    s += "ProtoSize: $ah.proto_size "
    s += if ah.op == u16(ArpOpcode.request) { "OP: Request " } 
         else if ah.op == u16(ArpOpcode.reply) { "OP: Reply "} 
         else { "OP: Unknown(0x${ah.op:04X})"}
    s += "SHA: ${ah.sha.to_string()} "
    s += "SPA: ${ah.spa.to_string()} "
    s += "THA: ${ah.tha.to_string()} "
    s += "TPA: ${ah.tpa.to_string()}"

    return s
}

struct ArpTableChans {
    insert_chan chan ArpTableCol
    update_chan chan ArpTableCol
    delete_chan chan ArpTableCol
    get_chan chan ArpTableCol
}

fn new_arp_table_chans() ArpTableChans {
    return ArpTableChans {
        insert_chan : chan ArpTableCol{}
        update_chan : chan ArpTableCol{}
        delete_chan : chan ArpTableCol{}
        get_chan : chan ArpTableCol{}
    }
}

struct ArpTableCol {
mut:
    mac PhysicalAddress
    ip  IPv4Address
    ttl time.Time
}

fn (ac ArpTableCol) to_string() string {
    ttl_sec := ac.ttl.unix_time() - time.now().unix_time()
    return "MACAddress:${ac.mac.to_string()} IPv4Address:${ac.ip.to_string()} " +
           "TTL: ${ttl_sec}sec"
}

struct ArpTable {
    my_mac PhysicalAddress
    my_ip IPv4Address
mut:
    table map[string]ArpTableCol
}

fn (mut at ArpTable) insert (col ArpTableCol) {
    at.table[col.ip.to_string()] = col
    at.table[col.ip.to_string()].ttl = time.now().add_seconds(30)
}

fn (mut at ArpTable) update (col ArpTableCol) {
    at.insert(col)
}

fn (mut at ArpTable) delete (col ArpTableCol) {
    at.table.delete(col.ip.to_string())
}

fn (mut at ArpTable) get(ip IPv4Address) ?ArpTableCol {
    if ip.to_string() == at.my_ip.to_string(){
        return ArpTableCol {
            mac: at.my_mac
            ip: at.my_ip
        }
    }
    return at.table[ip.to_string()]
}

fn (chans ArpTableChans) arp_table_thread(my_mac &PhysicalAddress, my_ip &IPv4Address) {
    mut arp_table := ArpTable{
        my_mac: *my_mac
        my_ip : *my_ip
    }
    for true {
        now := time.now()

        //println("ARP TIMER ${arp_table.table.keys()}")

        mut delete_targets := []ArpTableCol{}
        for i := 0; i < arp_table.table.len; i += 1 {
            col := arp_table.table[arp_table.table.keys()[i]]
            //println(col.to_string())
            if col.ttl.unix_time() < now.unix_time()  {
                //println("TIMEOUT!")
                delete_targets << col
            }
        }

        for del_col in delete_targets {
            arp_table.delete(del_col)
        }

        select {
            col := <- chans.insert_chan {
                arp_table.insert(col)
                res := arp_table.get(col.ip) or { ArpTableCol {}}
                println("[ARP TABLE] Inserted ${res.to_string()}")
            }
            col := <- chans.update_chan {
                arp_table.update(col)
                res := arp_table.get(col.ip) or { ArpTableCol {}}
                println("[ARP TABLE] Updated ${res.to_string()}")
            }
            col := <- chans.delete_chan {
                arp_table.delete(col)
                println("[ARP TABLE] Deleted ${col.to_string()}")
            }
            col := <- chans.get_chan {
                res := arp_table.get(col.ip) or { ArpTableCol {}}
                println("[ARP TABLE] Get ${res.to_string()}")
                chans.get_chan <- res
            }
            500 * time.millisecond {
            }
        }
    }
}