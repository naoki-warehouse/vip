module main

fn main(){
    mut netdev := new_netdevice() or { panic(err) }
    netdev.create_tap() or { panic(err) }
    println("NetDevice Info:\n" + netdev.str())

    for true {
        mut buf := []byte{len: 9000}
        count := C.read(netdev.tap_fd.fd, buf.data, sizeof(buf))
        println("recv $count")
        if count == 0 {
            continue
        }
        mut offset := 0
        mut pkt := new_packet()
        offset += pkt.parse_l2_header(buf[offset..])?
        offset += pkt.parse_l3_header(buf[offset..]) or { panic(err) }
        println("$pkt")
        netdev.handle_pkt(&pkt)
    }
}

