module main

import rand
import time
import net.unix

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

enum TcpState {
    syn_sent
    closed
    established
    close_wait
    last_ack
    fin_wait_1
    fin_wait_2
    closing
    time_out
}

struct TcpOps {
    msg IpcMsg
mut:
    ipc_sock unix.StreamConn
}

struct TcpSession {
mut:
    state TcpState
    peer_addr AddrInfo
    seq_num u32
    ack_num u32
    mss int = 1400
    recv_data []byte
    recv_data_head_num u32
    send_data []byte
    send_data_base_num u32
}

fn (nd &NetDevice) handle_tcp_sock(shared sock Socket) {
    mut sock_chan := TcpSocketChans{}
    mut fd := 0
    rlock {
        sock_chan = sock.tcp_chans
    }
    mut session := TcpSession{
        state: TcpState.closed
    }
    for {
        select {
            pkt := <- sock_chan.read_chan {
                mut port := u16(0)
                mut ttl := 0
                rlock sock {
                    port = sock.port
                    ttl = sock.ttl
                }
                recv_ipv4_hdr := pkt.l3_hdr.get_ipv4_hdr() or {continue}
                recv_tcp_hdr := pkt.l4_hdr.get_tcp_hdr() or {continue}
                if recv_ipv4_hdr.src_addr.to_string() != session.peer_addr.ipv4.to_string() {
                    continue
                }
                if recv_tcp_hdr.src_port != session.peer_addr.port {
                    continue
                }
                if session.state == TcpState.syn_sent {
                    if recv_tcp_hdr.control_flags ^ (tcp_syn|tcp_ack) != 0 {
                        continue
                    }
                    if recv_tcp_hdr.ack_num != session.seq_num + 1 {
                        continue
                    }
                    println("[TCP $fd] SYNACK received(SEQ_NUM:${recv_tcp_hdr.seq_num} ACK_NUM:${recv_tcp_hdr.ack_num})")
                    session.seq_num = recv_tcp_hdr.ack_num
                    session.ack_num = recv_tcp_hdr.seq_num + 1
                    mut tcp_hdr := TcpHdr {
                        src_port : port
                        dst_port : session.peer_addr.port
                        seq_num : session.seq_num
                        ack_num : session.ack_num
                        data_offset : 20
                        control_flags : u8(tcp_ack)
                        window_size: 4000
                    }
                    mut send_pkt := Packet{}
                    send_pkt.l4_hdr = tcp_hdr
                    nd.send_ipv4(mut send_pkt, &session.peer_addr, ttl) or {println("failed to send ack")}
                    session.send_data_base_num = session.seq_num
                    session.recv_data_head_num = session.ack_num
                    session.state = TcpState.established
                    println("[TCP $fd] Session established")
                } else if session.state == TcpState.established {
                    if recv_tcp_hdr.control_flags & tcp_ack > 0 && session.seq_num != recv_tcp_hdr.ack_num {
                        session.seq_num = recv_tcp_hdr.ack_num
                        mut buf_idx := int(0)
                        if session.seq_num > session.send_data_base_num {
                            buf_idx = int(session.seq_num - session.send_data_base_num)
                        } else {
                            buf_idx = int(u64(1 << 32) - u64(session.send_data_base_num - session.seq_num))
                        }
                        session.send_data = session.send_data[buf_idx..]
                        session.send_data_base_num = session.seq_num
                        println("[TCP $fd] Recv ack for send data(size:${buf_idx})")
                    }
                    if recv_tcp_hdr.seq_num == session.ack_num {
                        session.recv_data << pkt.payload
                        session.ack_num = recv_tcp_hdr.seq_num + u32(pkt.payload.len)
                        println("[TCP $fd] Recv data(size:${pkt.payload.len})")
                    }
                    if recv_tcp_hdr.control_flags & tcp_fin > 0 {
                        session.state = TcpState.close_wait
                        session.ack_num += 1
                    }
                    if recv_tcp_hdr.control_flags & tcp_psh > 0 {
                        mut tcp_hdr := TcpHdr {
                            src_port : port
                            dst_port : session.peer_addr.port
                            seq_num : session.seq_num
                            ack_num : session.ack_num
                            data_offset : 20
                            control_flags : u8(tcp_ack)
                            window_size: 4000
                        }
                        mut send_pkt := Packet{}
                        send_pkt.l4_hdr = tcp_hdr
                        nd.send_ipv4(mut send_pkt, &session.peer_addr, ttl) or {println("failed to send ack")}
                        continue
                    }
                }
            }
            mut op := <- sock_chan.control_chan {
                msg := op.msg.msg
                match msg {
                    IpcMsgSocket {
                        rlock {
                            fd = sock.fd
                        }
                        session = TcpSession {
                            state: TcpState.closed
                        }
                    }
                    IpcMsgConnect {
                        println("[TCP $fd] Connect")
                        nd.tcp_connect(msg, mut session, shared sock) or {println("[TCP $fd] failed to connect")}
                    }
                    IpcMsgPoll {
                        println("[TCP $fd] Poll")
                        nd.tcp_poll(msg, session, mut op.ipc_sock, shared sock) or {println("[TCP $fd] failed to poll")}
                        println("[TCP $fd] Poll success")
                        sock_chan.control_chan <- op
                    }
                    IpcMsgSockopt {
                        if msg.msg_type == C.IPC_GETSOCKOPT {
                            println("[TCP $fd] Getsockopt")
                            nd.tcp_getsockopt(msg, session, mut op.ipc_sock, shared sock) or {println("[TCP $fd] failed to getsockopt")}
                            println("[TCP $fd] Getsockopt success")
                            sock_chan.control_chan <- op
                        }
                    }
                    IpcMsgSockname {
                        if msg.msg_type == C.IPC_GETPEERNAME {
                            println("[TCP $fd] Getpeername")
                            nd.tcp_getpeername(msg, session, mut op.ipc_sock, shared sock) or {println("[TCP $fd] failed to getpeername")}
                            println("[TCP $fd] Getpeername success")
                            sock_chan.control_chan <- op
                        }
                    }
                    IpcMsgSendto {
                        println("[TCP $fd] Sendto")
                        rlock sock {
                            if sock.option_fd_nonblock {
                                sock_chan.control_chan <- op
                            }
                        }
                        nd.tcp_sendto(msg, mut session, shared sock) or {println("[TCP $fd] failed to sendto")}
                        println("[TCP $fd] Sendto success")
                        rlock sock {
                            if !sock.option_fd_nonblock {
                                sock_chan.control_chan <- op
                            }
                        }
                    }
                    IpcMsgRead {
                        println("[TCP $fd] Read")
                        nd.tcp_read(msg, mut session, mut op.ipc_sock, shared sock) or {println("[TCP $fd] failed to read")}
                        println("[TCP $fd] Read success")
                        sock_chan.control_chan <- op
                    }
                    IpcMsgClose {
                        println("[TCP $fd] Close")
                        nd.tcp_close(msg, mut session, &sock_chan, shared sock) or {println("[TCP $fd] failed to close")}
                        println("[TCP $fd] Close success")
                        sock_chan.control_chan <- op
                    }
                    else {}
                }
            }
            500 * time.millisecond {
            }
        }
    }
}

fn (nd &NetDevice) tcp_connect(msg &IpcMsgConnect, mut session TcpSession, shared sock Socket) ? {
    mut port := u16(0)
    mut ttl := 0
    rlock sock {
        port = sock.port
        ttl = sock.ttl
    }
    mut dst_addr := AddrInfo{}
    addr := msg.addr.addr
    match addr {
        SockAddrIn {
            dst_addr.ipv4 = addr.sin_addr
            dst_addr.port = addr.sin_port
        } else {}
    }
    session.seq_num = u16(rand.u32())
    mut tcp_hdr := TcpHdr {
        src_port : port
        dst_port : dst_addr.port
        seq_num : session.seq_num
        ack_num : 0
        data_offset : 20
        control_flags : u8(tcp_syn)
        window_size: 4000
    }
    mut pkt := Packet{}
    pkt.l4_hdr = tcp_hdr
    nd.send_ipv4(mut pkt, &dst_addr, ttl)?
    session.state = TcpState.syn_sent
    session.peer_addr = dst_addr
}

fn (nd &NetDevice) tcp_poll(msg &IpcMsgPoll, session &TcpSession, mut ipc_sock unix.StreamConn,  shared sock Socket) ? {
    mut res := *msg
    mut rc := 0
    for mut fd in res.fds {
        fd.revents = 0
        if fd.events & u16(C.POLLOUT | C.POLLWRNORM) > 0 {
            if session.state == TcpState.established {
                fd.revents |= fd.events & u16(C.POLLOUT | C.POLLWRNORM)
            }
        }
        if fd.events & u16(C.POLLIN) > 0 {
            if session.state != TcpState.closed && session.recv_data.len > 0 {
                fd.revents |= fd.events & u16(C.POLLIN)
            }
        }
    }

    for fd in res.fds {
        if fd.revents > 0 {
            rc += 1
        }
    }
    res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : rc
        err : 0
        data : res.to_bytes()[msg.IpcMsgBase.len+12..]
    }
    println("[IPC Poll] return ${res.to_string()}")
    ipc_sock.write(res_msg.to_bytes()) ?
}

fn (nd &NetDevice) tcp_getsockopt(msg &IpcMsgSockopt, session &TcpSession, mut ipc_sock unix.StreamConn, shared sock Socket) ? {
    mut res_sockopt := IpcMsgSockopt {
        IpcMsgBase : msg.IpcMsgBase
        fd : msg.fd
        level : msg.level
        optname : msg.optname
        optlen : msg.optlen
    }
    if msg.level == C.SOL_IP {

    } else if msg.level == C.SOL_SOCKET {
        if msg.optname == C.SO_ERROR {
            error_code := 0
            mut optval := []byte{len:4}
            copy(optval, int_to_bytes(error_code))
            res_sockopt.optval = optval
            res_msg := IpcMsgError {
                IpcMsgBase : msg.IpcMsgBase
                rc : 0
                err : 0
                data : res_sockopt.to_bytes()[msg.IpcMsgBase.len..]
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
    }
    res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : -1
        err : C.ENOPROTOOPT
    }
    println("[IPC Getsockopt] not supported option ${msg.to_string()}")
    ipc_sock.write(res_msg.to_bytes()) ?
}

fn (nd &NetDevice) tcp_getpeername(msg &IpcMsgSockname, session &TcpSession, mut ipc_sock unix.StreamConn, shared sock Socket) ? {
    mut sockaddr := SockAddrIn {
        family: u16(C.AF_INET)
        sin_addr: session.peer_addr.ipv4
        sin_port: session.peer_addr.port
    }

    mut res_sockname := IpcMsgSockname {
        IpcMsgBase : msg.IpcMsgBase
        socket: msg.socket
        address_len : u32(sockaddr.len)
        data: sockaddr.to_bytes()
    }

    mut res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : 0
        err : 0
        data : res_sockname.to_bytes()[msg.IpcMsgBase.len..]
    }

    println("[IPC Sockname] response addr(${sockaddr.to_string()})")
    ipc_sock.write(res_msg.to_bytes()) ?
}

fn (nd &NetDevice) tcp_sendto(msg &IpcMsgSendto, mut session &TcpSession, shared sock Socket) ? {
    mut port := u16(0)
    mut ttl := 0
    rlock sock {
        port = sock.port
        ttl = sock.ttl
    }
    for i := 0; i < msg.buf.len; i += session.mss {
        mut tcp_hdr := TcpHdr {
            src_port : port
            dst_port : session.peer_addr.port
            seq_num : u32(session.send_data_base_num + u32(session.send_data.len))
            ack_num : session.ack_num
            data_offset : 20
            control_flags : u8(tcp_psh|tcp_ack)
            window_size: 4000
        }
        mut send_pkt := Packet{}
        send_pkt.l4_hdr = tcp_hdr
        mut data_size := session.mss
        if i + data_size > msg.buf.len {
            data_size = msg.buf.len - i
        }
        send_pkt.payload = msg.buf[i..i+data_size]
        session.send_data << msg.buf[i..i+data_size]
        nd.send_ipv4(mut send_pkt, &session.peer_addr, ttl)?
    }
}

fn (nd &NetDevice) tcp_read(msg &IpcMsgRead, mut session TcpSession, mut ipc_sock unix.StreamConn, shared sock Socket) ? {
    mut res := *msg

    mut read_size := session.recv_data.len
    if read_size > msg.len {
        read_size = int(msg.len)
    }

    res.buf = session.recv_data[0..read_size]
    res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : read_size
        err : 0
        data : res.to_bytes()[msg.IpcMsgBase.len..]
    }
    ipc_sock.write(res_msg.to_bytes()) ?

    session.recv_data = session.recv_data[read_size..]
}

fn (nd &NetDevice) tcp_close(msg &IpcMsgClose, mut session TcpSession, sock_chan &TcpSocketChans, shared sock Socket) ? {
    mut port := u16(0)
    mut ttl := 0
    rlock sock {
        port = sock.port
        ttl = sock.ttl
    }

    mut tcp_hdr := TcpHdr {
        src_port : port
        dst_port : session.peer_addr.port
        seq_num : session.seq_num
        ack_num : session.ack_num
        data_offset : 20
        control_flags : u8(tcp_ack|tcp_fin)
        window_size: 4000
    }
    mut pkt := Packet{}
    pkt.l4_hdr = tcp_hdr
    nd.send_ipv4(mut pkt, &session.peer_addr, ttl)?
    if session.state == TcpState.close_wait {
        session.state = TcpState.last_ack
    } else if session.state == TcpState.established {
        session.state = TcpState.fin_wait_1
    }

    for {
        select {
            pkt_recv := <- sock_chan.read_chan {
                recv_tcp_hdr := pkt_recv.l4_hdr.get_tcp_hdr() ?
                if session.state == TcpState.last_ack {
                    if recv_tcp_hdr.ack_num != session.seq_num + 1 {
                        continue
                    }
                    if recv_tcp_hdr.seq_num != session.ack_num {
                        continue
                    }
                    if recv_tcp_hdr.control_flags & (tcp_ack) != tcp_ack {
                        continue
                    }

                    println("[TCP $msg.sockfd] Connection closed")
                    session.state = TcpState.closed
                    return
                }
                if session.state == TcpState.fin_wait_1 {
                    if recv_tcp_hdr.ack_num != session.seq_num + 1 {
                        continue
                    }
                    session.seq_num = recv_tcp_hdr.ack_num
                    if recv_tcp_hdr.seq_num != session.ack_num {
                        continue
                    }
                    if recv_tcp_hdr.control_flags & (tcp_ack) != tcp_ack {
                        continue
                    }
                    if recv_tcp_hdr.control_flags & (tcp_fin) != tcp_fin {
                        session.state = TcpState.fin_wait_2
                    }

                    session.state = TcpState.closing
                    session.ack_num += 1
                    tcp_hdr.seq_num = session.seq_num
                    tcp_hdr.ack_num = session.ack_num
                    tcp_hdr.control_flags = u8(tcp_ack)
                    nd.send_ipv4(mut pkt, &session.peer_addr, ttl)?
                    session.state = TcpState.closed
                    return
                }
            }   
            3 * time.second {
                nd.send_ipv4(mut pkt, &session.peer_addr, ttl)?
            }
        }
    }
}