module main

import os
import time
import rand

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
    threads []thread = []thread{}
    socks []Socket= []Socket{}
    sock_chan chan Socket
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


fn (mut nd NetDevice) handle_frame(buf []byte) ? {
    println("recv $buf.len")
    eth_hdr := parse_eth_hdr(buf) ?
    println("[ETH] $eth_hdr.to_string()")
    mut addr_info := AddrInfo {
        mac: eth_hdr.smac
    }
    if eth_hdr.ether_type == u16(EtherType.arp) {
        arp_hdr := parse_arp_hdr(buf[14..]) ?
        nd.handle_arp(&arp_hdr)
    } else if eth_hdr.ether_type == u16(EtherType.ipv4) {
        ipv4_hdr := parse_ipv4_hdr(buf[14..]) ?
        offset := ipv4_hdr.header_length + 14
        nd.handle_ipv4(&ipv4_hdr, buf[offset..], mut &addr_info) ?
    }
}

fn (mut nd NetDevice) handle_arp(arp_hdr &ArpHdr) {
    println("[ARP] $arp_hdr.to_string()")

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
            l4_hdr : HdrNone{}
            payload: []byte{}
        }

        nd.send_frame(pkt)
    } else if arp_hdr.op == u16(ArpOpcode.reply) {

    } else {

    }
}

fn (nd NetDevice) handle_ipv4(ipv4_hdr &IPv4Hdr, payload []byte, mut addr_info &AddrInfo) ? {
    println("[IPv4] ${ipv4_hdr.to_string()}")
    addr_info.ipv4 = ipv4_hdr.src_addr

    if ipv4_hdr.dst_addr.to_string() != nd.my_ip.to_string() {
        return
    }

    if ipv4_hdr.protocol == byte(IPv4Protocol.icmp) {
        icmp_hdr := parse_icmp_hdr(payload) ?
        nd.handle_icmp(&icmp_hdr, payload[4..], mut addr_info)
    }
}

fn (nd NetDevice) handle_icmp(icmp_hdr &IcmpHdr, payload []byte, mut addr_info &AddrInfo) {
    println("[ICMP] ${icmp_hdr.to_string()}")
    match icmp_hdr.hdr {
        IcmpHdrBase {
        }
        IcmpHdrEcho {
            nd.handle_icmp_echo(&icmp_hdr.hdr, payload[4..], mut addr_info)
        }
    }
}

fn (nd NetDevice) handle_icmp_echo(icmp_hdr_echo &IcmpHdrEcho, payload []byte, mut addr_info &AddrInfo) {
    if icmp_hdr_echo.icmp_type == byte(IcmpType.echo_request) {
        mut icmp_reply := *icmp_hdr_echo
        icmp_reply.chksum = 0
        icmp_reply.icmp_type = byte(IcmpType.echo_reply)

        mut reply_bytes := icmp_reply.to_bytes()
        reply_bytes << payload
        icmp_reply.chksum = calc_chksum(reply_bytes)

        mut pkt := Packet {
            l4_hdr : IcmpHdr {
                hdr: icmp_reply
            }
            payload : payload
        }
        nd.send_ipv4(mut &pkt, addr_info)
    }
}

fn (nd NetDevice) send_ipv4(mut pkt &Packet, dst_addr &AddrInfo) {
    mut ipv4_hdr := IPv4Hdr {}
    l4_hdr := &pkt.l4_hdr
    mut l4_size := 0
    match l4_hdr {
        IcmpHdr {
            l4_size = l4_hdr.len() + pkt.payload.len
            ipv4_hdr.protocol = byte(IPv4Protocol.icmp)
        }
        HdrNone {

        }
    }

    ipv4_hdr.tos = 0
    ipv4_hdr.total_len = u16(ipv4_hdr.header_length + l4_size)
    ipv4_hdr.id = u16(rand.u32() & 0xFFFF)
    ipv4_hdr.frag_flag = 0
    ipv4_hdr.frag_offset = 0
    ipv4_hdr.ttl = 64
    ipv4_hdr.chksum = 0
    ipv4_hdr.src_addr = nd.my_ip
    ipv4_hdr.dst_addr = dst_addr.ipv4

    ipv4_bytes := ipv4_hdr.to_bytes()
    ipv4_hdr.chksum = calc_chksum(ipv4_bytes)

    pkt.l3_hdr = ipv4_hdr

    nd.send_eth(mut pkt, dst_addr)
}

fn (nd NetDevice) send_eth(mut pkt &Packet, dst_addr &AddrInfo) {
    mut eth_hdr := EthHdr{
        dmac: dst_addr.mac
        smac: nd.my_mac
    }
    match pkt.l3_hdr {
        ArpHdr {
            eth_hdr.ether_type = u16(EtherType.arp)
        }
        IPv4Hdr {
            eth_hdr.ether_type = u16(EtherType.ipv4)
        }
        HdrNone {
        }
    }
    pkt.l2_hdr = eth_hdr

    nd.send_frame(pkt)
}

fn (nd NetDevice) send_frame(pkt &Packet) {
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
            l3_bytes = pkt.l3_hdr.to_bytes()
        }
        HdrNone {

        }
    }

    for i := 0; i < l3_bytes.len; i += 1 {
        buf[l3_offset + i] = l3_bytes[i]
    }
    size += l3_bytes.len

    l4_offset := size
    mut l4_bytes := []byte{}
    match pkt.l4_hdr {
        IcmpHdr {
            l4_bytes = pkt.l4_hdr.to_bytes()
        }
        HdrNone {

        }
    }

    for i := 0; i < l4_bytes.len; i += 1 {
        buf[l4_offset + i] = l4_bytes[i]
    }
    size += l4_bytes.len

    payload_offset := size
    for i := 0; i < pkt.payload.len; i += 1 {
        buf[payload_offset + i] = pkt.payload[i]
    }
    size += pkt.payload.len
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
    netdev.threads << go netdev.handle_control_usock("/tmp/vip.sock")


    for true {
        select {
            sock := <- netdev.sock_chan {
                netdev.socks << sock
                netdev.threads << go sock.handle_data(&netdev)
            }
            0 * time.millisecond {
                // select is not graceful for waiting timeout?
                set := C.fd_set{}
                C.FD_ZERO(&set)
                C.FD_SET(netdev.tap_fd, &set)
                timeout := C.timeval {
                    tv_sec: 0
                    tv_usec: 500 * 1000
                }
                err := C.@select(netdev.tap_fd + 1, &set, C.NULL, C.NULL, &timeout)
                if err < 0 {
                    panic("error!")
                }
                ready := C.FD_ISSET(netdev.tap_fd, &set)
                if !ready {
                   continue 
                }

                mut buf := [9000]byte{}
                count := C.read(netdev.tap_fd, &buf[0], sizeof(buf))
                netdev.handle_frame(buf[0..count]) ?
            }
        }
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

    mut err := C.ioctl(f.fd, C.TUNSETIFF, &ifr)
    if err < 0 {
        return error("falied to ioctl")
    }

    return f
}
