module main

#include <netinet/tcp.h>
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
mut:
    msg_flags int
    msg_controllen u64
    msg_iovlen u64
    msg_namelen u32
    msg_iovs_len []u64
    addr SockAddr
    recvmsg_cmsghdr []byte
    iov_data [][]byte
}

struct RecvmsgCmsgHdr {
    cmsg_len u64
    cmsg_level int
    cmsg_type int
mut:
    cmsg_data []byte
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
    if sock_type == C.SOCK_STREAM {
        return "SOCK_STREAM"
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
    if protocol == C.IPPROTO_TCP {
        return "IPPROTO_TCP"
    }
    return "$protocol"
}

fn level_to_string(level int) string {
    if level == C.SOL_SOCKET {
        return "SOL_SOCKET"
    }
    if level == C.SOL_IP {
        return "SOL_IP"
    }
    if level == C.SOL_TCP {
        return "SOL_TCP"
    }
    return "$level"
}

fn socket_optname_to_string(opt int) string {
    if opt == C.SO_SNDBUF {
        return "SO_SNDBUF"
    }
    if opt == C.SO_RCVBUF {
        return "SO_RCVBUF"
    }
    if opt == C.SO_TIMESTAMP_OLD {
        return "SO_TIMESTAMP_OLD"
    }
    if opt == C.SO_RCVTIMEO_OLD {
        return "SO_RCVTIMEO_OLD"
    }
    if opt == C.SO_SNDTIMEO_OLD {
        return "SO_SNDTIMEO_OLD"
    }
    if opt == C.SO_KEEPALIVE {
        return "SO_KEEPALIVE"
    }
    return "$opt"
}

fn ip_optname_to_string(opt int) string {
    if opt == C.IP_RECVERR {
        return "IP_RECVERR"
    }
    if opt == C.IP_RECVTTL {
        return "IP_RECVTTL"
    }
    if opt == C.IP_RETOPTS {
        return "IP_RETOPTS"
    }
    return "$opt"
}

fn tcp_optname_to_string(opt int) string {
    if opt == C.TCP_NODELAY {
        return "TCP_NODELAY"
    }
    if opt == C.TCP_KEEPIDLE {
        return "TCP_KEEPIDLE"
    }
    if opt == C.TCP_KEEPINTVL {
        return "TCP_KEEPINTVL"
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

    if base.msg_type == C.IPC_GETSOCKOPT ||
       base.msg_type == C.IPC_SETSOCKOPT {
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
    copy(buf[0..2], u16_to_bytes(im.msg_type))
    copy(buf[2..6], int_to_bytes(im.pid))
    return buf
}

fn (im IpcMsgError) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len: 8}
    copy(buf[0..4], int_to_bytes(im.rc))
    copy(buf[4..8], int_to_bytes(im.err))

    base_bytes << buf
    base_bytes << im.data

    return base_bytes
}

fn (im IpcMsgSockname) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len: 136}
    copy(buf[0..4], int_to_bytes(im.socket))
    copy(buf[4..8], u32_to_bytes(im.address_len))
    copy(buf[8..136], im.data)

    base_bytes << buf
    return  base_bytes
}

fn (im IpcMsgSockopt) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len:16 + int(im.optlen)}
    copy(buf[0..4], int_to_bytes(im.fd))
    copy(buf[4..8], int_to_bytes(im.level))
    copy(buf[8..12], int_to_bytes(im.optname))
    copy(buf[12..16], u32_to_bytes(im.optlen))
    copy(buf[16..16+im.optlen], im.optval)

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
    copy(buf[0..4], int_to_bytes(im.sockfd))
    copy(buf[4..8], int_to_bytes(im.flags))
    copy(buf[8..12], int_to_bytes(im.msg_flags))
    copy(buf[12..16], u32_to_bytes(im.msg_namelen))
    copy(buf[16..24], u64_to_bytes(im.msg_controllen))
    copy(buf[24..32], u64_to_bytes(im.msg_iovlen))
    for i := 0; i < im.msg_iovs_len.len; i += 1 {
        copy(buf[32+i*8..40+i*8], u64_to_bytes(im.msg_iovs_len[i]))
    }
    mut offset := 32 + im.msg_iovs_len.len*8
    sockaddr := im.addr.addr
    match sockaddr {
        SockAddrIn {
            copy(buf[offset..offset+16], sockaddr.to_bytes())
            offset += int(im.msg_namelen)
        }
        else { return error("not expected sockaddr")}
    }
    copy(buf[offset..offset+int(im.msg_controllen)], im.recvmsg_cmsghdr)
    offset += int(im.msg_controllen)
    mut iov_num := im.iov_data.len
    if iov_num > im.msg_iovlen {
        iov_num = int(im.msg_iovlen)
    }
    for i := 0; i < iov_num; i += 1 {
        copy(buf[offset..offset+int(im.msg_iovs_len[i])], im.iov_data[i])
        offset += int(im.msg_iovs_len[i])
    }

    base_bytes << buf
    return base_bytes
}

fn (im IpcMsgPoll) to_bytes() []byte {
    mut base_bytes := im.IpcMsgBase.to_bytes()
    mut buf := []byte{len:12 + int(im.nfds*8)}
    copy(buf[0..8], u64_to_bytes(im.nfds))
    copy(buf[8..12], int_to_bytes(im.timeout))
    mut offset := 12
    for i := 0; i < im.fds.len; i += 1 {
        fd := im.fds[i]
        copy(buf[offset..offset+4], int_to_bytes(fd.fd))
        copy(buf[offset+4..offset+6], u16_to_bytes(fd.events))
        copy(buf[offset+6..offset+8], u16_to_bytes(fd.revents))
        offset += 8
    }
    
    base_bytes << buf
    return base_bytes
}

fn (rc RecvmsgCmsgHdr) to_bytes() []byte {
    mut buf := []byte{len: int(((rc.cmsg_len-1)/8 + 1)*8)}
    copy(buf[0..8], u64_to_bytes(rc.cmsg_len))
    copy(buf[8..12], int_to_bytes(rc.cmsg_level))
    copy(buf[12..16], int_to_bytes(rc.cmsg_type))
    copy(buf[16..rc.cmsg_len], rc.cmsg_data)

    return buf
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
    if im.level == C.SOL_SOCKET {
        s += "optname:${socket_optname_to_string(im.optname)} "
    } else if im.level == C.SOL_IP {
        s += "optname:${ip_optname_to_string(im.optname)} "
    } else if im.level == C.SOL_TCP {
        s += "optname:${tcp_optname_to_string(im.optname)} "
    }
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
