module main

import time
import net.unix

#include "@VMODROOT/liblevelip/ipc.h"

struct Socket {
mut:
    pid int
    fd int
    domain int
    sock_type int
    protocol int
    port u16
    sock_chans SocketChans
    extended_recv_err bool
    option_ip_ttl bool
    option_ip_retopts bool
    ttl int = 64
    sndbuf_size int = 87380
    snd_timeout time.Duration
    rcvbuf_size int = 87380
    rcv_timeout time.Duration
    option_timestamp_old bool
    option_tcp_nodelay bool
    option_socket_keepalive bool
    option_tcp_keepidle int
    option_tcp_keepintvl int
    option_fd_nonblock bool
}

struct IpcSocket {
mut:
    stream unix.StreamConn
}

struct SocketChans {
    read_chan chan Packet
}

fn new_socket_chans() SocketChans {
    return SocketChans {
        read_chan : chan Packet{cap: 10}
    }
}

fn (nd NetDevice) handle_control_usock(usock_path string) {
    mut l := unix.listen_stream(usock_path) or { panic(err) }
    for {
        mut new_conn := l.accept() or { continue }
        println("new conn")
        nd.ipc_sock_chan <- IpcSocket {
            stream : new_conn
        }
    }
}

fn (shared sock Socket) handle_data(ipc_sock IpcSocket, nd &NetDevice, shared sock_shared SocketShared) {
    mut conn := ipc_sock.stream
    for {
        mut buf := []byte{len: 8192, init: 0}
        count := conn.read(mut buf) or {
            println('Server: connection drppped')
            break
        }
        if count <= 0 {
            continue
        }
        println("recv size:${count}")
        ipc_msg := parse_ipc_msg(buf) or { continue }
        msg := ipc_msg.msg
        match msg {
            IpcMsgBase {

            }
            IpcMsgSocket {
                sock.handle_socket(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgConnect {
                sock.handle_connect(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgSockname {
                sock.handle_sockname(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgClose {
                sock.handle_close(&msg, mut conn, nd, shared sock_shared) or { continue }
                break
            }
            IpcMsgSockopt {
                if msg.msg_type == C.IPC_GETSOCKOPT {
                    sock.handle_getsockopt(&msg, mut conn, nd, shared sock_shared) or { continue }
                } else if msg.msg_type == C.IPC_SETSOCKOPT {
                    sock.handle_setsockopt(&msg, mut conn, nd, shared sock_shared) or { continue }
                }
            }
            IpcMsgWrite {
                sock.handle_write(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgSendto {
                sock.handle_sendto(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgRecvmsg {
                sock.handle_recvmsg(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgPoll {
                sock.handle_poll(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
            IpcMsgFcntl {
                sock.handle_fcntl(&msg, mut conn, nd, shared sock_shared) or { continue }
            }
        }
    }

    println("[IPC] socket closed")
}

fn (shared sock Socket) handle_socket(msg &IpcMsgSocket, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Socket] ${msg.to_string()}")

    mut fd := 0
    mut port := u16(0)
    lock sock_shared {
        fd = sock_shared.fd_base
        port = sock_shared.udp_port_base
        sock_shared.fd_base += 1
        sock_shared.udp_port_base += 1
    }

    lock sock {
        sock.pid = msg.pid
        sock.fd = fd
        sock.domain = msg.domain
        sock.sock_type = msg.sock_type
        sock.protocol = msg.protocol
        sock.port = port
    }

    res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : fd
        err : 0
    }

    println("[IPC Socket] Assigned socket(fd:${fd})")
    res_msg_bytes := res_msg.to_bytes()
    ipc_sock.write(res_msg_bytes) ?
}

fn (shared sock Socket) handle_connect(msg &IpcMsgConnect, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Connect] ${msg.to_string()}")

    mut pkt := Packet {
        payload : []byte{len:100}
    }

    dst_addr := AddrInfo {
        mac: nd.my_mac
        ipv4: nd.my_ip
        port: sock.port
    }

    mut success := true
    mut port := u16(0)
    mut ttl := 0
    lock sock {
        port = sock.port
        ttl = sock.ttl
    }
    nd.send_udp(mut pkt, &dst_addr, port, ttl) or { success = false }

    if !success {
        res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
            rc : -1
            err : C.ETIMEDOUT
        }
        println("[IPC Connect] connect failed")
        ipc_sock.write(res_msg.to_bytes()) ?
    } else {
        res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
            rc : 0
        }
        println("[IPC Connect] connect success")
        ipc_sock.write(res_msg.to_bytes()) ?
    }

}

fn (shared sock Socket) handle_sockname(msg &IpcMsgSockname, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Sockname] ${msg.to_string()}")

    if msg.msg_type != C.IPC_GETSOCKNAME {
        return
    }

    mut sockaddr := SockAddrIn {
        family: u16(C.AF_INET)
        sin_addr: nd.my_ip
    }
    lock sock {
        sockaddr.sin_port = sock.port
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

fn (shared sock Socket) handle_close(msg &IpcMsgClose, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Close] ${msg.to_string()}")
    mut res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : 0
        err : 0
    }

    println("[IPC Close] close socket(fd:${msg.sockfd}")
    ipc_sock.write(res_msg.to_bytes()) ?
}

fn (shared sock Socket) handle_getsockopt(msg &IpcMsgSockopt, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Getsockopt] ${msg.to_string()}")

    mut res_sockopt := IpcMsgSockopt {
        IpcMsgBase : msg.IpcMsgBase
        fd : msg.fd
        level : msg.level
        optname : msg.optname
        optlen : msg.optlen
    }
    if msg.level == C.SOL_IP {

    } else if msg.level == C.SOL_SOCKET {
        if msg.optname == C.SO_RCVBUF {
            mut bufsize := 0
            rlock sock {
                bufsize = sock.rcvbuf_size
            }
            mut optval := []byte{len:4}
            copy(optval, int_to_bytes(bufsize))
            res_sockopt.optval = optval
            res_msg := IpcMsgError {
                IpcMsgBase : msg.IpcMsgBase
                rc : 0
                err : 0
                data : res_sockopt.to_bytes()[msg.IpcMsgBase.len..]
            }
            println("[IPC Getsockopt] Get recv buffer size ${bufsize}")
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

fn (shared sock Socket) handle_setsockopt(msg &IpcMsgSockopt, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Setsockopt] ${msg.to_string()}")

    mut res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : 0
        err : 0
    }
    if msg.level == C.SOL_IP {
        if msg.optname == C.IP_RECVERR {
            assert msg.optlen == 4
            rcv_err_enable := bytes_to_int(msg.optval[0..4]) ?
            if rcv_err_enable != 0 {
                println("[IPC Setsockopt] Enable extended recv error")
                lock sock {
                    sock.extended_recv_err = true
                }
            } else {
                println("[IPC Setsockopt] Disable extended recv error")
                lock sock {
                    sock.extended_recv_err = false
                }
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }

        if msg.optname == C.IP_RECVTTL {
            assert msg.optlen == 4
            flag := bytes_to_int(msg.optval[0..4]) ?
            if flag != 0 {
                println("[IPC Setsockopt] Enable ip recv ttl")
                lock sock {
                    sock.option_ip_ttl = true
                }
            } else {
                println("[IPC Setsockopt] Disable ip recv ttl")
                lock sock {
                    sock.option_ip_ttl = false
                }
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }

        if msg.optname == C.IP_RETOPTS {
            assert msg.optlen == 4
            flag := bytes_to_int(msg.optval[0..4]) ?
            if flag != 0 {
                println("[IPC Setsockopt] Enable ip reopts")
                lock sock {
                    sock.option_ip_retopts = true
                }
            } else {
                println("[IPC Setsockopt] Disable ip reopts")
                lock sock {
                    sock.option_ip_retopts = false
                }
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
    } else if msg.level == C.SOL_SOCKET {
        if msg.optname == C.SO_SNDBUF {
            assert msg.optlen == 4
            bufsize := bytes_to_int(msg.optval[0..4]) ?
            println("[IPC Setsockopt] Set send buffer size ${bufsize}")
            lock sock {
                sock.sndbuf_size = bufsize
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.SO_RCVBUF {
            assert msg.optlen == 4
            bufsize := bytes_to_int(msg.optval[0..4]) ?
            println("[IPC Setsockopt] Set recv buffer size ${bufsize}")
            lock sock {
                sock.rcvbuf_size = bufsize
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.SO_TIMESTAMP_OLD {
            assert msg.optlen == 4
            flag := bytes_to_int(msg.optval[0..4]) ?
            if flag != 0 {
                println("[IPC Setsockopt] Enable timestamp old")
                lock sock {
                    sock.option_timestamp_old = true
                }
            } else {
                println("[IPC Setsockopt] Disable timestamp old")
                lock sock {
                    sock.option_timestamp_old = false
                }
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.SO_SNDTIMEO_OLD {
            assert msg.optlen == 16
            tv_sec := i64(bytes_to_u64(msg.optval[0..8]) ?)
            tv_usec := i64(bytes_to_u64(msg.optval[8..16]) ?)
            timeout := tv_sec * time.second + tv_usec * time.microsecond
            println("[IPC Setsockopt] Set send timeout ${timeout/time.second} sec")
            lock sock {
                sock.snd_timeout = timeout
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.SO_RCVTIMEO_OLD {
            assert msg.optlen == 16
            tv_sec := i64(bytes_to_u64(msg.optval[0..8]) ?)
            tv_usec := i64(bytes_to_u64(msg.optval[8..16]) ?)
            timeout := tv_sec * time.second + tv_usec * time.microsecond
            println("[IPC Setsockopt] Set recv timeout ${timeout/time.second} sec")
            lock sock {
                sock.rcv_timeout = timeout
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.SO_KEEPALIVE {
            assert msg.optlen == 4
            flag := bytes_to_int(msg.optval[0..4]) ?
            if flag != 0 {
                println("[IPC Setsockopt] Enable socket keepalive")
                lock sock {
                    sock.option_socket_keepalive = true
                }
            } else {
                println("[IPC Setsockopt] Disable socket keepalive")
                lock sock {
                    sock.option_socket_keepalive = false
                }
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
    } else if msg.level == C.SOL_TCP {
        if msg.optname == C.TCP_NODELAY {
            assert msg.optlen == 4
            flag := bytes_to_int(msg.optval[0..4]) ?
            if flag != 0 {
                println("[IPC Setsockopt] Enable tcp nodelay")
                lock sock {
                    sock.option_tcp_nodelay = true
                }
            } else {
                println("[IPC Setsockopt] Disable tcp nodelay")
                lock sock {
                    sock.option_tcp_nodelay = false
                }
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.TCP_KEEPIDLE {
            assert msg.optlen == 4
            opt_sec := bytes_to_int(msg.optval[0..4]) ?
            println("[IPC Setsockopt] Set tcp keepalive idle ${opt_sec} sec")
            lock sock {
                sock.option_tcp_keepidle = opt_sec
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
        if msg.optname == C.TCP_KEEPINTVL {
            assert msg.optlen == 4
            opt_sec := bytes_to_int(msg.optval[0..4]) ?
            println("[IPC Setsockopt] Set tcp keepalive interval ${opt_sec} sec")
            lock sock {
                sock.option_tcp_keepintvl = opt_sec
            }
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }
    }

    println("[IPC Setsockopt] Unsupprted option")
    res_msg.rc = -1
    res_msg.err = C.ENOPROTOOPT
    ipc_sock.write(res_msg.to_bytes()) ?
}

fn (shared sock Socket) handle_write(msg &IpcMsgWrite, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Write] ${msg.to_string()}")
}

fn (shared sock Socket) handle_sendto(msg &IpcMsgSendto, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Sendto] ${msg.to_string()}")

    mut domain := 0
    mut sock_type := 0
    mut protocol := 0
    lock sock {
        domain = sock.domain
        sock_type = sock.sock_type
        protocol = sock.protocol
    }

    if domain == C.AF_INET &&
       sock_type == C.SOCK_DGRAM &&
       protocol == C.IPPROTO_ICMP {
        mut pkt := Packet{
            sockfd: msg.sockfd
        }
        parse_icmp_packet(mut pkt, msg.buf) ?
        println("[IPC Sendto] Send From IPv4 Layer")
        mut addr := SockAddrIn{}
        match msg.addr.addr {
            SockAddrBase {

            }
            SockAddrIn {
                addr = msg.addr.addr
            }
        }
        dest_addr := AddrInfo {
            ipv4: addr.sin_addr
        }

        mut success := true
        mut ttl := 0
        rlock {
            ttl = sock.ttl
        }
        nd.send_ipv4(mut pkt, dest_addr, ttl) or { success = false }

        mut res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
            rc : 0
            err : 0
        }
        println("[IPC Sendto] ${res_msg.to_string()}")
        if !success {
            res_msg.rc = -1
            // is this ok ?
            res_msg.err = C.EBADF
            println("[IPC Sendto] sendto failed")
        } else {
            res_msg.rc = int(msg.buf.len)
            println("[IPC Sendto] sendto success")
        }
        res_msg_bytes := res_msg.to_bytes()
        ipc_sock.write(res_msg_bytes) ?
        mut s := ""
        for i := 0; i < 6; i += 1 {
            s += "0x${res_msg_bytes[i]:02X} "
        }
        println(s)
    }
}

fn (shared sock Socket) handle_recvmsg(msg &IpcMsgRecvmsg, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Recvmsg] ${msg.to_string()}")

    println("[IPC Recvmsg] try to get packet")
    mut sock_chans := SocketChans{}
    mut timeout := 10 * time.second
    mut timeout_enable := false
    mut ip_ttl := false
    mut timestamp := false
    rlock sock {
        sock_chans = sock.sock_chans
        if sock.rcv_timeout > 0 {
            timeout = sock.rcv_timeout
            timeout_enable = true
        }
        if sock.option_ip_ttl {
            ip_ttl = true
        }
        if sock.option_timestamp_old {
            timestamp = true
        }
    }
    mut pkt := Packet{}
    println("[IPC Recvmsg] read_chan.len:${sock_chans.read_chan.len}")
    for {
        select {
            pkt = <- sock_chans.read_chan {
                break
            }
            timeout * time.nanosecond {
                if !timeout_enable {
                    println("[IPC Recvmsg] timeout disabled")
                    continue
                }
                println("[IPC Recvmsg] timeout")
                res_msg := IpcMsgError {
                    IpcMsgBase : msg.IpcMsgBase
                    rc : -1
                    err : C.EAGAIN
                }
                ipc_sock.write(res_msg.to_bytes()) ?
                return
            }
        }
    }
    println("[IPC Recvmsg] get packet")

    mut buf := []byte{}
    l4_hdr := pkt.l4_hdr
    match l4_hdr {
        IcmpHdr {
            buf = l4_hdr.to_bytes()
        }
        else {}
    }
    buf << pkt.payload
    mut res := *msg
    res.iov_data << buf
    l3_hdr := pkt.l3_hdr
    match l3_hdr {
        IPv4Hdr {
            res.msg_namelen = 16
            res.addr = SockAddr {
                addr : SockAddrIn {
                    sin_addr : l3_hdr.src_addr
                }
            }
        }
        else {}
    }

    if ip_ttl {
        match l3_hdr {
            IPv4Hdr {
                cmsg_hdr := RecvmsgCmsgHdr {
                    cmsg_len : 20
                    cmsg_level : C.SOL_IP
                    cmsg_type : C.IP_TTL
                    cmsg_data : int_to_bytes(l3_hdr.ttl)
                }
                res.recvmsg_cmsghdr << cmsg_hdr.to_bytes()
            } else {}
        }
    }

    if timestamp {
        tv_sec_bytes := i64_to_bytes(pkt.timestamp.unix)
        tv_usec_bytes := i64_to_bytes(pkt.timestamp.microsecond)
        mut cmsg_hdr := RecvmsgCmsgHdr {
            cmsg_len : 32
            cmsg_level : C.SOL_SOCKET
            cmsg_type : C.SO_TIMESTAMP_OLD
        }
        cmsg_hdr.cmsg_data << tv_sec_bytes
        cmsg_hdr.cmsg_data << tv_usec_bytes
        res.recvmsg_cmsghdr << cmsg_hdr.to_bytes()
    }

    res.msg_controllen = u64(res.recvmsg_cmsghdr.len)

    mut res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : buf.len
        err : 0
        data : res.to_bytes()?[msg.IpcMsgBase.len..]
    }

    res_msg_bytes := res_msg.to_bytes()
    println("[IPC Recvmsg] recvmsg success(size:${res_msg_bytes.len})")
    ipc_sock.write(res_msg_bytes) ?
}


fn (shared sock Socket) handle_poll(msg &IpcMsgPoll, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Poll] ${msg.to_string()}")

    mut res := *msg
    mut rc := 0
    for mut fd in res.fds {
        fd.revents = 0
        if fd.events & u16(C.POLLIN) > 0 {
            mut pkt := Packet{}
            select {
                pkt = <- sock.sock_chans.read_chan {
                    sock.sock_chans.read_chan <- pkt
                    fd.revents |= u16(C.POLLIN)
                    rc += 1
                }
                msg.timeout * time.millisecond {
                }
            }
        }
    }

    res_msg := IpcMsgError {
        IpcMsgBase : msg.IpcMsgBase
        rc : rc
        err : 0
        data : res.to_bytes()[msg.IpcMsgBase.len+12..]
    }
    println("[IPC Poll] poll success")
    ipc_sock.write(res_msg.to_bytes()) ?
}

fn (shared sock Socket) handle_fcntl(msg &IpcMsgFcntl, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Fcntl] ${msg.to_string()}")

    if msg.cmd == C.F_GETFL {
        mut flag := C.O_RDWR
        rlock sock {
            if sock.option_fd_nonblock {
                flag |= C.O_NONBLOCK
            }
        }
        res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
            rc : flag
        }
        println("[IPC Fcntl] F_GETFL result:0x${flag:04X}")
        ipc_sock.write(res_msg.to_bytes()) ?
        return
    }
    if msg.cmd == C.F_SETFL {
        mut flag := bytes_to_int(msg.data[0..4]) ?
        flag = flag & (~C.O_RDWR)
        lock sock {
            if sock.option_fd_nonblock && (flag & C.O_NONBLOCK == 0) {
                println("[IPC Fcntl] F_SETFL disable nonblock")
                sock.option_fd_nonblock = false
            }
        }
        if flag & C.O_NONBLOCK > 0 {
            println("[IPC Fcntl] F_SETFL enable nonblock")
            lock sock {
                sock.option_fd_nonblock = true
            }
            flag = flag & (~C.O_NONBLOCK)
        }

        if flag != 0 {
            res_msg := IpcMsgError {
                IpcMsgBase : msg.IpcMsgBase
                rc : -1
                err : C.EINVAL
            }
            println("[IPC Fcntl] F_SETFL failed to configure 0x${flag:04X}")
            ipc_sock.write(res_msg.to_bytes()) ?
            return
        }

        res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
        }
        println("[IPC Fcntl] F_SETFL success")
        ipc_sock.write(res_msg.to_bytes())?
        return
    }
}