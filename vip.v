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
    socks []shared Socket= []shared Socket{}
    ipc_sock_chan chan IpcSocket
    lo_chan chan Packet
}

struct SocketShared {
mut:
    fd_base int = 4097
    udp_port_base u16 = 49152
    tcp_port_base u16 = 49152
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
    netdev.lo_chan = chan Packet{cap: 10}
    return netdev
}

fn (nd NetDevice) print() {
    println("Netdev")
    println("- TAP Device Name: ${nd.tap_name}")
    println("- My MAC Address : ${nd.my_mac.to_string()}")
    println("- My IP Address  : ${nd.my_ip.to_string()}")
}


fn (mut nd NetDevice) handle_frame(pkt &Packet) ? {
    println("[ETH] $pkt.l2_hdr.to_string()")
    if pkt.sockfd != 1 {
        l3_hdr := pkt.l3_hdr
        match l3_hdr {
            ArpHdr {
                nd.handle_arp(pkt, &l3_hdr)
            }
            IPv4Hdr {
                nd.handle_ipv4(pkt, &l3_hdr) ?
            }
            HdrNone {}
        }
    }
    for i := 0; i < nd.socks.len; i += 1 {
       shared sock := nd.socks[i]
       rlock sock {
           if !(sock.domain == C.AF_INET &&
              sock.sock_type == C.SOCK_DGRAM &&
              sock.protocol == C.IPPROTO_ICMP) {
               continue
           }

           if pkt.sockfd == sock.fd {
               continue
           }

           if !pkt.is_icmp_packet() {
               continue
           }

           println("[ICMP] handling sock(fd:${sock.fd}")
           res := sock.sock_chans.read_chan.try_push(pkt)
           println("[ICMP] handle sock(fd:${sock.fd})")
           println("[ICMP] sock_chans.read_chan.len:${sock.sock_chans.read_chan.len}")
           if res != .success {
               println("[ICMP] failed to push read_chan(fd:${sock.fd})")
           }
       }
    }
}

fn (mut nd NetDevice) handle_arp(pkt &Packet, arp_hdr &ArpHdr) {
    println("[ARP] $arp_hdr.to_string()")
    arp_col := ArpTableCol{
        mac: arp_hdr.sha
        ip: arp_hdr.spa
    }
    nd.arp_table_chans.insert_chan <- arp_col

    if arp_hdr.tpa.to_string() != nd.my_ip.to_string() {
        return
    }

    res := nd.get_arp_col(arp_hdr.spa)
    assert arp_col.ip.to_string() == res.ip.to_string()
    assert arp_col.mac.to_string() == res.mac.to_string()

    if arp_hdr.op == u16(ArpOpcode.request) {
        mut send_pkt := Packet {
            l4_hdr : HdrNone{}
            payload: []byte{}
        }

        dst_addr := AddrInfo {
            mac: arp_hdr.sha
            ipv4: arp_hdr.spa
        }
        nd.send_arp(mut send_pkt, &dst_addr, u16(ArpOpcode.reply)) or { println(("failed to send arp reply"))}
    } else if arp_hdr.op == u16(ArpOpcode.reply) {

    } else {

    }
}

fn (nd NetDevice) get_arp_col(ip IPv4Address) ArpTableCol {
    arp_col := ArpTableCol{
        ip: ip
    }
    nd.arp_table_chans.get_chan <- arp_col
    res := <- nd.arp_table_chans.get_chan

    return res
}

fn (nd NetDevice) handle_ipv4(pkt &Packet, ipv4_hdr &IPv4Hdr) ? {
    println("[IPv4] ${ipv4_hdr.to_string()}")

    if ipv4_hdr.dst_addr.to_string() != nd.my_ip.to_string() {
        return
    }

    l4_hdr := pkt.l4_hdr
    match l4_hdr {
        IcmpHdr {
            nd.handle_icmp(pkt, &l4_hdr)
        }
        UdpHdr {
        }
        HdrNone {
        }
    }
}

fn (nd NetDevice) handle_icmp(pkt &Packet, icmp_hdr &IcmpHdr) {
    println("[ICMP] ${icmp_hdr.to_string()}")
    match icmp_hdr.hdr {
        IcmpHdrBase {
        }
        IcmpHdrEcho {
            nd.handle_icmp_echo(pkt, &icmp_hdr.hdr)
        }
    }
}

fn (nd NetDevice) handle_icmp_echo(pkt &Packet, icmp_hdr_echo &IcmpHdrEcho) {
    addr_info := AddrInfo {
        ipv4 : pkt.l3_hdr.get_ipv4_hdr() or {return}.src_addr
    }
    if icmp_hdr_echo.icmp_type == byte(IcmpType.echo_request) {
        mut icmp_reply := *icmp_hdr_echo
        icmp_reply.chksum = 0
        icmp_reply.icmp_type = byte(IcmpType.echo_reply)

        mut reply_bytes := icmp_reply.to_bytes()
        reply_bytes << pkt.payload
        icmp_reply.chksum = calc_chksum(reply_bytes)

        mut send_pkt := Packet {
            l4_hdr : IcmpHdr {
                hdr: icmp_reply
            }
            payload : pkt.payload
        }
        nd.send_ipv4(mut send_pkt, addr_info) or { println("failed to send icmp reply")}
    }
}

fn (nd NetDevice) send_arp(mut pkt Packet, dst_addr &AddrInfo, op u16) ? {
    mut arp_req := ArpHdr {
        hw_type : u16(ArpHWType.ethernet)
        hw_size: 6
        proto_type: u16(ArpProtoType.ipv4)
        proto_size: 4
        op: u16(op)
        sha: nd.my_mac
        spa: nd.my_ip
        tha: dst_addr.mac
        tpa: dst_addr.ipv4
    }

    pkt.l3_hdr = arp_req
    nd.send_eth(mut pkt, dst_addr) ?
}

fn (nd NetDevice) send_udp(mut pkt &Packet, dst_addr &AddrInfo, src_port u16) ? {
    mut udp_hdr := UdpHdr {
        src_port : src_port
        dst_port : dst_addr.port
        chksum : 0
    }
    udp_hdr.segment_length = u16(udp_hdr.len() + pkt.payload.len)

    pkt.l4_hdr = udp_hdr
    nd.send_ipv4(mut pkt, dst_addr) ?
}

fn (nd NetDevice) send_ipv4(mut pkt &Packet, dst_addr &AddrInfo) ? {
    mut ipv4_hdr := IPv4Hdr {}
    mut l4_hdr := &pkt.l4_hdr
    mut l4_size := 0
    match mut l4_hdr {
        IcmpHdr {
            l4_size = l4_hdr.len() + pkt.payload.len
            ipv4_hdr.protocol = byte(IPv4Protocol.icmp)
        }
        UdpHdr {
            l4_size = l4_hdr.len() + pkt.payload.len
            ipv4_hdr.protocol = byte(IPv4Protocol.udp)
            ph := PseudoHdr {
                src_ip : nd.my_ip,
                dst_ip : dst_addr.ipv4
                protocol : ipv4_hdr.protocol
                udp_length : u16(l4_size)
            }
            mut pseudo_bytes := ph.to_bytes()
            pseudo_bytes << l4_hdr.to_bytes()
            pseudo_bytes << pkt.payload
            l4_hdr.chksum = calc_chksum(pseudo_bytes)
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

    nd.send_eth(mut pkt, dst_addr) ?
}

fn (nd NetDevice) send_eth(mut pkt &Packet, dst_addr &AddrInfo) ? {
    mut eth_hdr := EthHdr{
        smac: nd.my_mac
    }
    l3_hdr := pkt.l3_hdr
    match l3_hdr {
        ArpHdr {
            addr_bytes := dst_addr.mac.addr
            if addr_bytes[0] + addr_bytes[1] + addr_bytes[2] + addr_bytes[3] == 0 {
                eth_hdr.dmac = physical_address_bcast()
            } else {
                eth_hdr.dmac = l3_hdr.tha
            }
            eth_hdr.ether_type = u16(EtherType.arp)
        }
        IPv4Hdr {
            mut dmac_rev := nd.get_arp_col(l3_hdr.dst_addr)
            mut arp_try_num := 0
            for dmac_rev.ip.to_string() != l3_hdr.dst_addr.to_string()  && arp_try_num < 10 {
                println("Resolving ARP...")
                mut arp_pkt := Packet {
                    l4_hdr : HdrNone{}
                    payload: []byte{}
                }
                arp_req_addr := AddrInfo {
                    ipv4: l3_hdr.dst_addr
                }
                nd.send_arp(mut arp_pkt, &arp_req_addr, u16(ArpOpcode.request)) ?
                time.sleep(100 * time.millisecond)
                dmac_rev = nd.get_arp_col(l3_hdr.dst_addr)
                arp_try_num += 1
            }
            if arp_try_num == 10 {
                return error("failed to resolve ${l3_hdr.dst_addr.to_string()}")
            }
            eth_hdr.dmac = dmac_rev.mac
            eth_hdr.ether_type = u16(EtherType.ipv4)
        }
        HdrNone {
        }
    }
    pkt.l2_hdr = eth_hdr

    nd.send_frame(mut pkt)
}

fn (nd NetDevice) send_frame(mut pkt Packet) {
    if pkt.l2_hdr.dmac.to_string() == nd.my_mac.to_string() {
        if pkt.sockfd == 0 {
            pkt.sockfd = 1
        }
        res := nd.lo_chan.try_push(pkt)
        println("[ETH] sockfd:${pkt.sockfd} lo_chan.len:${nd.lo_chan.len}")
        if res != .success {
            println("[ETH] failed to push lo_chan")
        }
        return
    }

    mut buf := []byte{len:9000}
    mut size := 0

    eth_bytes := pkt.l2_hdr.to_bytes()
    copy(buf[0..], eth_bytes)
    l3_offset := eth_bytes.len
    size = l3_offset

    mut l3_bytes := []byte{}
    l3_hdr := pkt.l3_hdr
    match l3_hdr {
        ArpHdr {
            l3_bytes = l3_hdr.to_bytes()
        }
        IPv4Hdr {
            l3_bytes = l3_hdr.to_bytes()
        }
        HdrNone {

        }
    }

    copy(buf[l3_offset..], l3_bytes)
    size += l3_bytes.len

    l4_offset := size
    mut l4_bytes := []byte{}
    l4_hdr := pkt.l4_hdr
    match l4_hdr {
        IcmpHdr {
            l4_bytes = l4_hdr.to_bytes()
        }
        UdpHdr {
            l4_bytes = l4_hdr.to_bytes()
        }
        HdrNone {

        }
    }

    copy(buf[l4_offset..], l4_bytes)
    size += l4_bytes.len

    payload_offset := size
    copy(buf[payload_offset..], pkt.payload)
    size += pkt.payload.len
    C.write(nd.tap_fd, buf.data, size)
    println("SEND FRAME")
}

fn (nd NetDevice) timer() {
    for true {
        time.sleep(500 * time.millisecond)
    }
}

fn main() {
    mut netdev := init_netdevice() ?
    netdev.print()

    shared sock_shared := SocketShared {}

    netdev.threads << go netdev.arp_table_chans.arp_table_thread(&netdev.my_mac, &netdev.my_ip)
    netdev.threads << go netdev.handle_control_usock("/tmp/vip.sock")

    for true {
        select {
            ipc_sock := <- netdev.ipc_sock_chan {
                shared sock := Socket {
                    sock_chans : new_socket_chans()
                }
                netdev.socks << sock
                netdev.threads << go sock.handle_data(ipc_sock, &netdev, shared sock_shared)
            }
            pkt := <- netdev.lo_chan {
                netdev.handle_frame(&pkt) ?
            }
            0 * time.millisecond {
                // select is not graceful for waiting timeout?
                set := C.fd_set{}
                C.FD_ZERO(&set)
                C.FD_SET(netdev.tap_fd, &set)
                timeout := C.timeval {
                    tv_sec: 0
                    tv_usec: 50 * 1000
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
                println("recv $count")
                mut pkt := Packet{}
                parse_eth_frame(mut pkt, buf[0..count]) or { continue }
                netdev.handle_frame(&pkt) ?
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
