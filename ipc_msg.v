module main

type IpcMsgType = IpcMsgBase | IpcMsgSocket | IpcMsgConnect | IpcMsgSockname | IpcMsgClose | IpcMsgSockopt | IpcMsgWrite | IpcMsgSendto | IpcMsgRecvmsg | IpcMsgPoll

struct IpcMsg {
    msg IpcMsgType
}

struct IpcMsgBase {
    len int = 6
    msg_type u16
    pid int
}

struct IpcMsgSocket {
    IpcMsgBase
    domain int
    sock_type int
    protocol int
}

struct IpcMsgError {
    IpcMsgBase
mut:
    rc int
    err int
    data []byte
}

struct IpcMsgConnect {
    IpcMsgBase
    sockfd int
    addr SockAddr
    addrlen u32
}

struct IpcMsgSockname {
    IpcMsgBase
    socket int
    address_len u32
    data []byte
}

struct IpcMsgClose {
    IpcMsgBase
    sockfd int
}

struct IpcMsgSockopt {
    IpcMsgBase
    fd int
    level int
    optname int
    optlen u32
mut:
    optval []byte
}

struct IpcMsgWrite {
    IpcMsgBase
    sockfd int
    len u64
mut:
    buf []byte
}

struct IpcMsgSendto {
    IpcMsgBase
    sockfd int
    flags int
    addrlen u32
mut:
    addr SockAddr
    len u64
    buf []byte
}

struct IpcMsgRecvmsg {
    IpcMsgBase
    sockfd int
    flags int
    msg_flags int
    msg_controllen u64
    msg_iovlen u64
mut:
    msg_namelen u32
    msg_iovs_len []u64
    addr SockAddr
    recvmsg_cmsghdr []byte
    iov_data [][]byte
}

struct IpcMsgPollfd {
    fd int
    events u16
mut:
    revents u16
}

struct IpcMsgPoll {
    IpcMsgBase
    nfds u64
    timeout int
mut:
    fds []IpcMsgPollfd
}

fn bytes_to_u16(buf []byte) ?u16 {
    assert buf.len == 2
    return buf[0] | buf[1] << 8
}

fn bytes_to_int(buf []byte) ?int {
    assert buf.len == 4
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24
}

fn bytes_to_u32(buf []byte) ?u32 {
    assert buf.len == 4
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24
}

fn bytes_to_u64(buf []byte) ?u64 {
    assert buf.len == 8
    mut tmp := u64(0)
    tmp |= buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24
    tmp |= buf[4] << 32 | buf[5] << 40 | buf[6] << 48 | buf[7] << 56
    return tmp
}

fn domain_to_string(domain int) string {
    if domain == C.AF_INET {
        return "AF_INET"
    }
    return "$domain"
}

fn type_to_string(sock_type int) string {
    if sock_type == C.SOCK_DGRAM {
        return "SOCK_DGRAM"
    }
    return "$sock_type"
}

fn protocol_to_string(protocol int) string {
    if protocol == C.IPPROTO_ICMP {
        return "IPPROTO_ICMP"
    }
    if protocol == C.IPPROTO_IP {
        return "IPPROTO_IP"
    }
    return "$protocol"
}

fn level_to_string(level int) string {
    if level == C.SOL_SOCKET {
        return "SOL_SOCKET"
    }
    return "$level"
}

fn optname_to_string(opt int) string {
    if opt == C.SO_RCVBUF {
        return "SO_RCVBUF"
    }
    return "$opt"
}

fn events_to_string(events u16) string {
    mut s := ""
    mut e := events
    for {
        old_e := e
        if e & u16(C.POLLIN) > 0 {
            s += "|POLLIN"
            e &= ~u16(C.POLLIN)
        }

        if e == 0 {
            break
        }

        if old_e == e {
            s += " 0x${e}"
            break
        }
    }

    if s == "" {
        return ""
    } else {
        return s[1..]
    }
}

fn parse_ipc_msg(buf []byte) ?IpcMsg {
    assert buf.len >= 6
    base := IpcMsgBase {
        msg_type : buf[0] | buf[1] << 8
        pid : bytes_to_int(buf[2..6]) ?
    }

    if base.msg_type == C.IPC_SOCKET {
        assert buf.len >= 18
        return IpcMsg {
            msg: IpcMsgSocket {
                IpcMsgBase : base
                domain : bytes_to_int(buf[6..10]) ?
                sock_type : bytes_to_int(buf[10..14]) ?
                protocol : bytes_to_int(buf[14..18]) ?
            }
        }
    }
    if base.msg_type == C.IPC_CONNECT {
        assert buf.len >= 30
        return IpcMsg {
            msg: IpcMsgConnect {
                IpcMsgBase: base
                sockfd : bytes_to_int(buf[6..10]) ?
                addr : parse_sockaddr(buf[10..26]) ?
                addrlen: bytes_to_u32(buf[26..30]) ?
            }
        }
    }

    if base.msg_type == C.IPC_GETSOCKNAME {
        assert buf.len >= 142
        return IpcMsg {
            msg: IpcMsgSockname {
                IpcMsgBase: base
                socket: bytes_to_int(buf[6..10]) ?
                address_len : bytes_to_u32(buf[10..14]) ?
                data : buf[14..142]
            }
        }
    }

    if base.msg_type == C.IPC_CLOSE {
        assert buf.len >= 10
        return IpcMsg {
            msg: IpcMsgClose {
                IpcMsgBase: base
                sockfd: bytes_to_int(buf[6..10]) ?
            }
        }
    }

    if base.msg_type == C.IPC_GETSOCKOPT {
        assert buf.len >= 22
        return IpcMsg {
            msg: IpcMsgSockopt{
                IpcMsgBase: base
                fd: bytes_to_int(buf[6..10]) ?
                level: bytes_to_int(buf[10..14]) ?
                optname: bytes_to_int(buf[14..18]) ?
                optlen: bytes_to_u32(buf[18..22]) ?
                optval: buf[22..]
            }
        }
    }

    if base.msg_type == C.IPC_WRITE {
        assert buf.len >= 14
        mut msg := IpcMsgWrite {
            IpcMsgBase : base
            sockfd : bytes_to_int(buf[6..10]) ?
            len : bytes_to_u64(buf[10..18]) ?
        }
        msg.buf = buf[18..18 + msg.len]
        return IpcMsg {
            msg : msg
        }
    }

    if base.msg_type == C.IPC_SENDTO {
        mut msg := IpcMsgSendto {
            IpcMsgBase : base
            sockfd : bytes_to_int(buf[6..10]) ?
            flags : bytes_to_int(buf[10..14]) ?
            addrlen : bytes_to_u32(buf[14..18]) ?
        }
        msg.addr = parse_sockaddr(buf[18..18 + int(msg.addrlen)]) ?
        mut offset := 18 + int(msg.addrlen)
        msg.len = bytes_to_u64(buf[offset..offset+8]) ?
        offset += 8
        msg.buf = buf[offset..u64(offset) + msg.len]
        return IpcMsg {
            msg: msg
        }
    }

    if base.msg_type == C.IPC_RECVMSG {
        mut msg := IpcMsgRecvmsg {
            IpcMsgBase : base
            sockfd : bytes_to_int(buf[6..10]) ?
            flags : bytes_to_int(buf[10..14]) ?
            msg_flags : bytes_to_int(buf[14..18]) ?
            msg_namelen : bytes_to_u32(buf[18..22]) ?
            msg_controllen : bytes_to_u64(buf[22..30]) ?
            msg_iovlen : bytes_to_u64(buf[30..38]) ?
        }
        for i := 0; i < msg.msg_iovlen; i += 1 {
            msg.msg_iovs_len << bytes_to_u64(buf[38 + i*8..46 + i*8]) ?
        }
        return IpcMsg {
            msg: msg
        }
    }

    if base.msg_type == C.IPC_POLL {
        mut msg := IpcMsgPoll {
            IpcMsgBase: base
            nfds : bytes_to_u64(buf[6..14]) ?
            timeout: bytes_to_int(buf[14..18]) ?
            fds : []IpcMsgPollfd{}
        }
        for i := 0; i < msg.nfds; i += 1 {
            offset := 18 + i*8
            poolfd := IpcMsgPollfd {
                fd : bytes_to_int(buf[offset..offset+4]) ?
                events : bytes_to_u16(buf[offset+4..offset+6]) ?
                revents : bytes_to_u16(buf[offset+6..offset+8]) ?
            }
            msg.fds << poolfd
        }

        return IpcMsg {
            msg : msg
        }
    }

    return IpcMsg {
        msg : base
    }
}

fn (im IpcMsgBase) to_bytes() []byte {
    mut buf := []byte{len: 6}
    buf[0] = byte(im.msg_type)
    buf[1] = byte(im.msg_type >> 8)
    buf[2] = byte(im.pid)
    buf[3] = byte(im.pid >> 8)
    buf[4] = byte(im.pid >> 16)
    buf[5] = byte(im.pid >> 24)
    
    return buf
}

fn (im IpcMsgError) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len: 8}
    buf[0] = byte(im.rc)
    buf[1] = byte(im.rc >> 8)
    buf[2] = byte(im.rc >> 16)
    buf[3] = byte(im.rc >> 24)
    buf[4] = byte(im.err)
    buf[5] = byte(im.err >> 8)
    buf[6] = byte(im.err >> 16)
    buf[7] = byte(im.err >> 24)

    base_bytes << buf
    base_bytes << im.data

    return base_bytes
}

fn (im IpcMsgSockname) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len: 136}
    buf[0] = byte(im.socket)
    buf[1] = byte(im.socket >> 8)
    buf[2] = byte(im.socket >> 16)
    buf[3] = byte(im.socket >> 24)
    buf[4] = byte(im.address_len)
    buf[5] = byte(im.address_len >> 8)
    buf[6] = byte(im.address_len >> 16)
    buf[7] = byte(im.address_len >> 24)

    mut data_size := im.data.len
    if data_size >= 128 {
        data_size = 128
    }
    for i := 0; i < data_size; i += 1 {
        buf[i+8] = im.data[i]
    }

    base_bytes << buf
    return  base_bytes
}

fn (im IpcMsgSockopt) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len:16 + int(im.optlen)}
    buf[0] = byte(im.fd)
    buf[1] = byte(im.fd >> 8)
    buf[2] = byte(im.fd >> 16)
    buf[3] = byte(im.fd >> 24)
    buf[4] = byte(im.level)
    buf[5] = byte(im.level >> 8)
    buf[6] = byte(im.level >> 16)
    buf[7] = byte(im.level >> 24)
    buf[8] = byte(im.optname)
    buf[9] = byte(im.optname >> 8)
    buf[10] = byte(im.optname >> 16)
    buf[11] = byte(im.optname >> 24)
    buf[12] = byte(im.optlen)
    buf[13] = byte(im.optlen >> 8)
    buf[14] = byte(im.optlen >> 16)
    buf[15] = byte(im.optlen >> 24)

    mut data_size := im.optval.len
    if data_size > im.optlen {
        data_size = int(im.optlen)
    }
    for i := 0; i < data_size; i += 1 {
        buf[i+16] = im.optval[i]
    }

    base_bytes << buf
    return base_bytes
}

fn (im IpcMsgRecvmsg) to_bytes() ?[]byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut iov_len_sum := u64(0)
    for iov_len in im.msg_iovs_len {
        iov_len_sum += iov_len
    }

    mut buf := []byte{len:32 + int(im.msg_iovs_len.len*8) + int(im.msg_namelen) + int(im.msg_controllen) + int(iov_len_sum)}
    for i := 0; i < 4; i += 1 {
        buf[i] = byte(im.sockfd >> i*8)
    }
    for i := 0; i < 4; i += 1 {
        buf[i+4] = byte(im.flags >> i*8)
    }
    for i := 0; i < 4; i += 1 {
        buf[i+8] = byte(im.msg_flags >> i*8)
    }
    for i := 0; i < 4; i += 1 {
        buf[i+12] = byte(im.msg_namelen >> i*8)
    }
    for i := 0; i < 8; i += 1 {
        buf[i+16] = byte(im.msg_controllen >> i*8)
    }
    for i := 0; i < 8; i += 1 {
        buf[i+24] = byte(im.msg_iovlen >> i*8)
    }
    for j := 0; j < im.msg_iovs_len.len; j += 1 {
        for i := 0; i < 8; i += 1 {
            buf[32+j*8+i] = byte(im.msg_iovs_len[j] >> i*8)
        }
    }
    mut offset := 32 + im.msg_iovs_len.len*8
    sockaddr := im.addr.addr
    match sockaddr {
        SockAddrIn {
            sockaddr_bytes := sockaddr.to_bytes()
            assert sockaddr_bytes.len == 16
            for i := 0; i < 16; i += 1 {
                buf[offset+i] = sockaddr_bytes[i]
            }
            offset += int(im.msg_namelen)
        }
        else { return error("not expected sockaddr")}
    }
    mut cmsghdr_size := im.recvmsg_cmsghdr.len
    if cmsghdr_size > im.msg_controllen {
        cmsghdr_size = int(im.msg_controllen)
    }
    for i := 0; i < cmsghdr_size; i += 1 {
        buf[offset+i] = im.recvmsg_cmsghdr[i]
    }
    offset += int(im.msg_controllen)
    mut iov_num := im.iov_data.len
    if iov_num > im.msg_iovlen {
        iov_num = int(im.msg_iovlen)
    }
    for j := 0; j < iov_num; j += 1 {
        iov_buf := im.iov_data[j]
        mut iov_buf_len := iov_buf.len
        if iov_buf_len > im.msg_iovs_len[j] {
            iov_buf_len = int(im.msg_iovs_len[j])
        }
        for i := 0; i < iov_buf_len; i += 1 {
            buf[offset+i] = iov_buf[i]
        }
        offset += int(im.msg_iovs_len[j])
    }

    base_bytes << buf
    return base_bytes
}

fn (im IpcMsgPoll) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len:12 + int(im.nfds*8)}

    for i := 0; i < 8; i += 1 {
        buf[i] = byte(im.nfds >> i*8)
    }
    for i := 0; i < 4; i += 1 {
        buf[i+8] = byte(im.timeout >> i*8)
    }
    mut offset := 12
    for j := 0; j < im.fds.len; j += 1 {
        fd := im.fds[j]
        for i := 0; i < 4; i += 1 {
            buf[offset+i] = byte(fd.fd >> i*8)
        }
        buf[offset+4] = byte(fd.events)
        buf[offset+5] = byte(fd.events >> 8)
        buf[offset+6] = byte(fd.revents)
        buf[offset+7] = byte(fd.revents >> 8)
        offset += 8
    }
    
    base_bytes << buf
    return base_bytes
}

fn (im IpcMsgBase) to_string() string {
    mut s := "type:0x${im.msg_type:04X} "
    s += "pid:${im.pid}"

    return s
}

fn (im IpcMsgSocket) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "domain:${domain_to_string(im.domain)} "
    s += "type:${type_to_string(im.sock_type)} "
    s += "protocol:${protocol_to_string(im.protocol)}"

    return s
}

fn (im IpcMsgConnect) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "sockfd:${im.sockfd} "
    s += "addr:${im.addr.to_string()} "
    s += "addrlen:${im.addrlen}"

    return s
}

fn (im IpcMsgSockopt) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "fd:${im.fd} "
    s += "level:${level_to_string(im.level)} "
    s += "optname:${optname_to_string(im.optname)} "
    s += "optlen:${im.optlen} "

    return s
}

fn (im IpcMsgWrite) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "sockfd:${im.sockfd} "
    s += "len:${im.len}"

    return s
}

fn (im IpcMsgSendto) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "sockfd:${im.sockfd} "
    s += "flags:${im.flags} "
    s += "addrlen:${im.addrlen} "
    s += "addr:${im.addr.to_string()} "
    s += "len:${im.len}"

    return s
}

fn (im IpcMsgRecvmsg) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "sockfd:${im.sockfd} "
    s += "flags:${im.flags} "
    s += "msg_flags:${im.msg_flags} "
    s += "msg_namelen:${im.msg_namelen} "
    s += "msg_controllen:${im.msg_controllen} "
    s += "msg_iovlen:${im.msg_iovlen} "
    s += "msg:iovs_len:${im.msg_iovs_len}"

    return s
}

fn (im IpcMsgPoll) to_string() string {
    mut s := im.IpcMsgBase.to_string() + " "
    s += "nfds:${im.nfds} "
    s += "timeout:${im.timeout} "
    for fd in im.fds {
        s += "[fd:${fd.fd} "
        s += "events:${events_to_string(fd.events)} "
        s += "revents:${events_to_string(fd.revents)}]"
    }
    return s
}
