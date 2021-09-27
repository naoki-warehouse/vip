module main

const (
    tcp_fin = 0b000001
    tcp_syn = 0b000010
    tcp_rst = 0b000100
    tcp_psh = 0b001000
    tcp_ack = 0b010000
    tcp_urg = 0b100000
)
struct TcpHdr {
mut:
    src_port u16
    dst_port u16
    seq_num u32
    ack_num u32
    data_offset int
    control_flags u8
    window_size u16
    chksum u16
    urg_ptr u16
    options []TcpOptionInterface = []TcpOptionInterface{}
}

interface TcpOptionInterface {
    kind byte
    length byte
    to_string() string
}
enum TcpOptionKind {
    nop = 0x1
    mss = 0x2
    window_scale = 0x3
    sack_permitted = 0x4
    timestamp = 0x8
}

struct TcpOptionBase {
    kind byte
mut:
    length byte
}

struct TcpOptionNop {
    TcpOptionBase
}

struct TcpOptionMss {
    TcpOptionBase
    mss u16
}

struct TcpOptionWindowScale {
    TcpOptionBase
    window_scale byte
}

struct TcpOptionSackPermitted {
    TcpOptionBase
}

struct TcpOptionTimestamp {
    TcpOptionBase
    timestamp u32
    timestamp_echo_reply u32
}

fn parse_tcp_hdr(buf []byte) ?TcpHdr {
    assert buf.len >=  20
    mut tcp_hdr := TcpHdr {
        src_port : be16(buf[0..2])
        dst_port : be16(buf[2..4])
        seq_num : be_bytes_to_u32(buf[4..8]) ?
        ack_num : be_bytes_to_u32(buf[8..12]) ?
        data_offset: (buf[12] >> 4) * 4
        control_flags : (buf[13])
        window_size : be16(buf[14..16])
        chksum : be16(buf[16..18])
        urg_ptr : be16(buf[18..20])
    }
    assert buf.len >= tcp_hdr.data_offset
    for i := 20; i < tcp_hdr.data_offset; {
        if buf[i] == 0 {
            break
        }
        if buf[i] == byte(TcpOptionKind.nop) {
            i += 1
            continue
        }
        tcp_option := parse_tcp_option(buf[i..]) ?
        tcp_hdr.options << tcp_option  
        i += tcp_option.length
    }

    return tcp_hdr
}

fn parse_tcp_option(buf []byte) ?TcpOptionInterface {
    assert buf.len >= 1
    mut base := TcpOptionBase {
        kind: buf[0]
    }
    if base.kind == byte(TcpOptionKind.nop) {
        return TcpOptionNop {
            kind: byte(TcpOptionKind.nop)
            length: 1
        }
    }
    base.length = buf[1]
    if base.kind == byte(TcpOptionKind.mss) {
        assert buf.len >= 4
        return TcpOptionMss {
            TcpOptionBase: base
            mss: be16(buf[2..4])
        }
    }
    if base.kind == byte(TcpOptionKind.window_scale) {
        assert buf.len >= 3
        return TcpOptionWindowScale {
            TcpOptionBase: base
            window_scale: buf[2]
        }
    }
    if base.kind == byte(TcpOptionKind.sack_permitted) {
        assert buf.len >= 2
        return TcpOptionSackPermitted {
            TcpOptionBase: base
        }
    }
    if base.kind == byte(TcpOptionKind.timestamp) {
        assert buf.len >= 10
        return TcpOptionTimestamp {
            TcpOptionBase: base
            timestamp: be_bytes_to_u32(buf[2..6]) ?
            timestamp_echo_reply: be_bytes_to_u32(buf[6..10]) ?
        }
    }
    return base
}

fn (th &TcpHdr) to_bytes() []byte {
    mut buf := []byte{len:th.data_offset}

    copy(buf[0..2], be_u16_to_bytes(th.src_port))
    copy(buf[2..4], be_u16_to_bytes(th.dst_port))
    copy(buf[4..8], be_u32_to_bytes(th.seq_num))
    copy(buf[8..12], be_u32_to_bytes(th.ack_num))
    buf[12] = byte((th.data_offset / 4) << 4)
    buf[13] = th.control_flags
    copy(buf[14..16], be_u16_to_bytes(th.window_size))
    copy(buf[16..18], be_u16_to_bytes(th.chksum))
    copy(buf[18..20], be_u16_to_bytes(th.urg_ptr))

    return buf
}

fn (th &TcpHdr) control_flag_to_string() string {
    mut s := "["
    mut flag := th.control_flags
    if flag & tcp_fin > 0 {
        s += "FIN,"
        flag &= ~(tcp_fin)
    }
    if flag & tcp_syn > 0 {
        s += "SYN,"
        flag &= ~(tcp_syn)
    }
    if flag & tcp_rst > 0 {
        s += "RST,"
        flag &= ~(tcp_rst)
    }
    if flag & tcp_psh > 0 {
        s += "PSH,"
        flag &= ~(tcp_psh)
    }
    if flag & tcp_ack > 0 {
        s += "ACK,"
        flag &= ~(tcp_ack)
    }
    if flag & tcp_urg > 0 {
        s += "URG,"
        flag &= ~(tcp_urg)
    }
    if flag > 0 {
        s += "0b${flag:06b},"
    }
    if s.len != 1 {
        s = s[..s.len-1]
    }
    s += "]"
    return s
}

fn (th &TcpHdr) to_string() string {
    mut s := "src_port:${th.src_port} "
    s += "dst_port:${th.dst_port} "
    s += "seq_num:0x${th.seq_num:04X} "
    s += "ack_num:0x${th.ack_num:04X} "
    s += "data_offset:${th.data_offset} "
    s += "control_flags:${th.control_flag_to_string()} "
    s += "window_size:${th.window_size} "
    s += "chksum:0x${th.chksum:04X} "
    s += "urg_ptr:0x${th.urg_ptr:04X} "
    s += "options:["
    for option in th.options {
        s += option.to_string() + ","
    }
    s = s[..s.len-1] + "]"

    return s
}

fn (to &TcpOptionBase) to_string() string {
    return "kind:${to.kind} len:${to.length}"
}

fn (to &TcpOptionNop) to_string() string {
    return to.TcpOptionBase.to_string()
}

fn (to &TcpOptionMss) to_string() string {
    return to.TcpOptionBase.to_string() + " mss:${to.mss}"
}

fn (to &TcpOptionWindowScale) to_string() string {
    return to.TcpOptionBase.to_string() + " window scale:${to.window_scale}"
}

fn (to &TcpOptionTimestamp) to_string() string {
    mut s := to.TcpOptionBase.to_string() + " "
    s += "timestamp:${to.timestamp} "
    s += "timestamp_echo_reply:${to.timestamp_echo_reply}"
    return s
}

fn (to &TcpOptionSackPermitted) to_string() string {
    return to.TcpOptionBase.to_string()
}