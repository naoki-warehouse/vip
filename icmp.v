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
