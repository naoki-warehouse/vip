module main

import time

fn main(){
    mut netdev := new_netdevice() or { panic(err) }
    netdev.create_tap() or { panic(err) }
    println("NetDevice Info:\n" + netdev.str())

    go arp_handler(new_arp_handler(&netdev))
    go icmp_handler(new_icmp_handler(&netdev))
    go netdevice_send(&netdev)
    go netdevice_recv(&netdev)
    netdev_chan := new_netdevice_channel(netdev.send_chan)
    shared at := netdev.arp_table
    udp_sock := new_socket(&netdev, netdev_chan, shared at)
    for true {
        println("HOGE")
        dst_addr := SocketAddress{
            physical_addr: parse_physical_address("5a:6e:6a:0c:2c:5d") or { panic(err) }
            ip_addr: parse_ip_address("192.168.10.1") or { panic(err) }
            port: 1234
        }
        mut buf := []byte{len: 100}
        buf[0] = 0xde
        buf[1] = 0xff
        buf[2] = 0xd3
        pkt := udp_sock.create_udp(buf, &dst_addr) or { panic(err) }
        udp_sock.netdevice_chan.send_chan <- &pkt
        time.sleep(1 * time.second)
    }
}

fn netdevice_recv(nd &NetDevice) {
    mut buf := [9000]byte{}
    for true {
        count := C.read(nd.tap_fd.fd, &buf[0], sizeof(buf))
        println("recv $count")
        if count == 0 {
            continue
        }
        pkt := parse_packet(buf[0..count]) or { panic(err) }
    	mut sock_addr := SocketAddress{}
        l2_hdr := pkt.l2_hdr
        match l2_hdr {
            HdrNone { return }
            EthHdr {
                sock_addr.physical_addr = l2_hdr.smac
            }
        }
        l3_hdr := pkt.l3_hdr
        match l3_hdr {
            HdrNone {

            }
            ArpHdr {
                nd.arp_chan.recv_chan <- &pkt
            }
            IpHdr {
                nd.handle_ip(&pkt)
            }
        }
    }
}

fn netdevice_send(nd &NetDevice) {
	mut buf := []byte{len:9000}
    for true {
        pkt := <- nd.send_chan
	    send_size := pkt.write_bytes(mut buf) or { panic(err) }
	    C.write(nd.tap_fd.fd, buf.data, send_size)
    }
}
