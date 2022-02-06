module main

import net.conv

[packed]
struct IcmpHdrBase {
    icmp_type u8
    code u8
    chksum u16
}

enum IcmpType {
    echo_reply = 0
    echo_request = 8
}

[packed]
struct IcmpHdrEcho {
    id u16
    seq_num u16
}

struct IcmpHdrUnknown {}

type IcmpHdrType = IcmpHdrUnknown | IcmpHdrEcho

struct IcmpHdr {
    base &IcmpHdrBase
mut:
    typ  &IcmpHdrType
}

fn parse_icmp_header(buf []byte) ?&IcmpHdr {
    assert buf.len >= sizeof(IcmpHdrBase)

    base := unsafe { &IcmpHdrBase(&buf[0]) }
    mut icmp_hdr := IcmpHdr {
        base: base
        typ: &IcmpHdrUnknown{}
    }

    if base.icmp_type == u8(IcmpType.echo_reply) || 
       base.icmp_type == u8(IcmpType.echo_request) {
           icmp_hdr.typ = unsafe { &IcmpHdrEcho(&buf[sizeof(IcmpHdrBase)])}
    }

    return &icmp_hdr
}

fn (ih &IcmpHdrBase) len() int {
    return int(sizeof(IcmpHdrBase))
}

fn (ih &IcmpHdr) len() int {
    typ := ih.typ
    mut len := sizeof(IcmpHdrBase)
    match typ {
        IcmpHdrUnknown {
        }
        IcmpHdrEcho {
            len += sizeof(IcmpHdrEcho)
        }
    }

    return int(len)
}

fn (ih &IcmpHdrBase) str() string {
    mut s := "type:${ih.icmp_type} "
    s += "code:${ih.code} "
    s += "chksum:0x${ih.chksum:04X}"

    return s
}

fn (ih &IcmpHdrUnknown) str() string {
    return ""
}

fn (ih &IcmpHdrEcho) str() string {
    mut s := "id:0x${conv.nth16(ih.id):04X} "
    s += "seq_num:0x${conv.nth16(ih.seq_num):04X}"

    return s
}

fn (ih &IcmpHdr) str() string {
    return ih.base.str() + " " + ih.typ.str()
}

fn (ih &IcmpHdrBase) write_bytes(mut buf []byte) ?int {
    assert buf.len >= ih.len()

    mut offset := 0
    buf[offset] = ih.icmp_type
    offset += 1
    buf[offset] = ih.code
    offset += 1
    offset += copy(buf[offset..], le_u16_to_bytes(0))
    
    return offset
}

fn (ih &IcmpHdrEcho) write_bytes(mut buf []byte) ?int {
    assert buf.len >= sizeof(IcmpHdrEcho)
    mut offset := 0
    offset += copy(buf[offset..], le_u16_to_bytes(ih.id))
    offset += copy(buf[offset..], le_u16_to_bytes(ih.seq_num))

    return offset
}

fn (ih &IcmpHdr) write_bytes(mut buf []byte) ?int {
    mut offset := 0
    offset += ih.base.write_bytes(mut buf[offset..])?
    typ := ih.typ
    match typ {
        IcmpHdrUnknown {}
        IcmpHdrEcho {
            offset += typ.write_bytes(mut buf[offset..])?
        }
    }
    return offset
}

fn (sock &IcmpHandler) handle_icmp(pkt &Packet, icmp &IcmpHdr, sock_addr &SocketAddress) {
	icmp_typ := icmp.typ
	match icmp_typ {
		IcmpHdrUnknown {}
		IcmpHdrEcho {
			sock.handle_icmp_echo(pkt, icmp_typ, sock_addr)
		}
	}
}

fn (sock &IcmpHandler) handle_icmp_echo(pkt &Packet, icmp &IcmpHdrEcho, sock_addr &SocketAddress) {
    /*
	println("$icmp")
	mut s := "payload: ["
	for i := 0; i < pkt.payload.len; i += 1 {
		s += "0x${pkt.payload[i]:02X} "
	}
	s += "]"
	println(s)
    */

	mut res_pkt := Packet {
		l2_hdr: &HdrNone {}
		l3_hdr: &HdrNone {}
		l4_hdr: &IcmpHdr {
			base: &IcmpHdrBase {
				icmp_type: u8(IcmpType.echo_reply)
				code: 0
				chksum: 0
			}
			typ: &IcmpHdrEcho {
				id: icmp.id
				seq_num: icmp.seq_num
			}
		}
		payload: pkt.payload
	}

    sock.create_ip(mut res_pkt, sock_addr) or { panic(err) }
    sock.netdevice_chan.send_chan <- &res_pkt
}

struct IcmpHandler {
    Socket
}

fn new_icmp_handler(nd &NetDevice) IcmpHandler {
    shared at := nd.arp_table
    return IcmpHandler {
        new_socket(nd, nd.icmp_chan, shared at)
    }
}

fn icmp_handler(ih IcmpHandler) {
    mut sock := ih
    for true {
        pkt := <- sock.netdevice_chan.recv_chan
        mut sock_addr := SocketAddress{}
        l2_hdr := pkt.l2_hdr
        match l2_hdr {
            HdrNone { continue }
            EthHdr {
                sock_addr.physical_addr = l2_hdr.smac
            }
        }
        l3_hdr := pkt.l3_hdr
        match l3_hdr {
            HdrNone { continue }
            ArpHdr { continue}
            IpHdr { 
                sock_addr.ip_addr = l3_hdr.base.src_addr
            }
        }
        l4_hdr := pkt.l4_hdr
        match l4_hdr {
            HdrNone { continue }
            IcmpHdr { 
                sock.handle_icmp(pkt, l4_hdr, sock_addr)
            }
        }
    }
}