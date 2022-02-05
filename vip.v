module main

fn main(){
    mut netdev := new_netdevice() or { panic(err) }
    netdev.create_tap() or { panic(err) }
    println("NetDevice Info:\n" + netdev.str())

    for true {
        mut buf := [9000]byte{}
        count := C.read(netdev.tap_fd.fd, &buf[0], sizeof(buf))
        println("recv $count")
        if count == 0 {
            continue
        }
        mut pkt := parse_packet(buf[0..count]) or { panic(err) }
        println("$pkt")
        netdev.handle_pkt(&pkt)
    }
}

