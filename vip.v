module main

import os
import time

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct NetDevice {
mut:
    tap_fd int
    tap_name string
    my_mac PhysicalAddress
    my_ip IPv4Address

    arp_table_chans ArpTableChans

    threads []thread
}

fn be16(buf []byte) u16 {
    assert buf.len == 2
    return buf[0] << 8 | buf[1]
}

fn C.ioctl(fd int, request u64, arg voidptr) int

//const ifname_size = C.IFNAMSIZ
const ifname_size = 16

struct C.ifreq {
mut:
    ifr_name [ifname_size]char
    ifr_flags u16
}

fn init_netdevice() ?NetDevice {
    mut netdev := NetDevice{}

    netdev.my_mac.addr[0] = 0x52
    netdev.my_mac.addr[1] = 0x54
    netdev.my_mac.addr[2] = 0x00
    netdev.my_mac.addr[3] = 0x4D
    netdev.my_mac.addr[4] = 0x3F
    netdev.my_mac.addr[5] = 0xE4
    netdev.my_ip.addr[0] = 192
    netdev.my_ip.addr[1] = 168
    netdev.my_ip.addr[2] = 10
    netdev.my_ip.addr[3] = 2

    netdev.tap_name = "test_tap"
    f := tap_alloc(netdev.tap_name) ?
    netdev.tap_fd = f.fd
    netdev.arp_table_chans = new_arp_table_chans()
    return netdev
}

fn (nd NetDevice) print() {
    println("Netdev")
    println("- TAP Device Name: ${nd.tap_name}")
    println("- My MAC Address : ${nd.my_mac.to_string()}")
    println("- My IP Address  : ${nd.my_ip.to_string()}")
}


fn (mut nd NetDevice) handle_frame(buf []byte, recv_size int) ? {
    println("recv $recv_size")
    eth_hdr := parse_eth_hdr(buf, recv_size, 0) ?
    println("[ETH] $eth_hdr.to_string()")
    if eth_hdr.ether_type == u16(EtherType.arp) {
        arp_hdr := parse_arp_hdr(buf[14..]) ?
        println("[ARP] $arp_hdr.to_string()")
        nd.handle_arp(&arp_hdr)
    }
}

fn (mut nd NetDevice) handle_arp(arp_hdr &ArpHdr) {
    arp_col := ArpTableCol{
        mac: arp_hdr.sha
        ip: arp_hdr.spa
    }
    nd.arp_table_chans.insert_chan <- arp_col

    nd.arp_table_chans.get_chan <- arp_col
    res := <- nd.arp_table_chans.get_chan
    assert arp_col.ip.to_string() == res.ip.to_string()
    assert arp_col.mac.to_string() == res.mac.to_string()

    //println("RESPONSE ${res.to_string()}")

    if arp_hdr.tpa.to_string() != nd.my_ip.to_string() {
        return
    }

    if arp_hdr.op == u16(ArpOpcode.request) {
        arp_req := ArpHdr {
            hw_type : u16(ArpHWType.ethernet)
            hw_size: 6
            proto_type: u16(ArpProtoType.ipv4)
            proto_size: 4
            op: u16(ArpOpcode.reply)
            sha: nd.my_mac
            spa: nd.my_ip
            tha: arp_hdr.sha
            tpa: arp_hdr.spa
        }

        eth_req := EthHdr {
            dmac : arp_hdr.sha
            smac : nd.my_mac
            ether_type : u16(EtherType.arp)
        }

        pkt := Packet {
            l2_hdr : eth_req
            l3_hdr : arp_req
        }

        nd.send_frame(pkt)
    } else if arp_hdr.op == u16(ArpOpcode.reply) {

    } else {

    }
}

fn (nd NetDevice) send_frame(pkt Packet) {
    mut buf := [9000]byte{}
    mut size := 0

    eth_bytes := pkt.l2_hdr.to_bytes()
    for i := 0; i < eth_bytes.len; i += 1 {
        buf[i] = eth_bytes[i]
    }
    l3_offset := eth_bytes.len
    size = l3_offset

    mut l3_bytes := []byte{}
    match pkt.l3_hdr {
        ArpHdr {
            l3_bytes = pkt.l3_hdr.to_bytes()
        }
        IPv4Hdr {

        }
    }

    for i := 0; i < l3_bytes.len; i += 1 {
        buf[l3_offset + i] = l3_bytes[i]
    }

    size += l3_bytes.len
    println("SEND FRAME")
    C.write(nd.tap_fd, &buf, size)
}

fn (nd NetDevice) timer() {
    for true {
        time.sleep(500 * time.millisecond)
    }
}

fn main() {
    mut netdev := init_netdevice() ?
    netdev.print()

    netdev.threads << go netdev.arp_table_chans.arp_table_thread()

    for true {
        mut buf := [9000]byte{}
        count := C.read(netdev.tap_fd, &buf[0], sizeof(buf))
        netdev.handle_frame(buf[0..], count) ?
    }
}

fn tap_alloc(tun_dev_name string) ?os.File{
    mut f := os.File{}
    mut ifr := C.ifreq{}
    f = os.open_file("/dev/net/tun", "r+") ?

    ifr.ifr_flags = u16(C.IFF_TAP | C.IFF_NO_PI)
    mut idx := 0
    for mut c in ifr.ifr_name {
        if idx >= tun_dev_name.len {
            c = 0
        } else {
            c = tun_dev_name[idx]
        }
        idx++
    }

    err := C.ioctl(f.fd, C.TUNSETIFF, &ifr)
    if err < 0 {
        return error("falied to ioctl")
    }

    return f
}
