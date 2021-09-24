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
                sock.handle_sockopt(&msg, mut conn, nd, shared sock_shared) or { continue }
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
    lock sock {
        port = sock.port
    }
    nd.send_udp(mut pkt, &dst_addr, port) or { success = false }

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

fn (shared sock Socket) handle_sockopt(msg &IpcMsgSockopt, mut ipc_sock unix.StreamConn, nd &NetDevice, shared sock_shared SocketShared) ? {
    println("[IPC Sockopt] ${msg.to_string()}")

    mut res_sockopt := IpcMsgSockopt {
        IpcMsgBase : msg.IpcMsgBase
        fd : msg.fd
        level : msg.level
        optname : msg.optname
        optlen : msg.optlen
    }
    if msg.optname == C.SO_RCVBUF {
        rcv_buf_size  := 128 * 1024
        mut optval := []byte{len:4}
        copy(optval, int_to_bytes(rcv_buf_size))
        res_sockopt.optval = optval
        res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
            rc : 0
            err : 0
            data : res_sockopt.to_bytes()[msg.IpcMsgBase.len..]
        }
        println("[IPC Sockopt] SO_RCVBUF: $rcv_buf_size")
        ipc_sock.write(res_msg.to_bytes()) ?
    } else {
        res_msg := IpcMsgError {
            IpcMsgBase : msg.IpcMsgBase
            rc : -1
            err : C.ENOPROTOOPT
        }
        println("[IPC Sockopt] not supported option ${msg.to_string()}")
        ipc_sock.write(res_msg.to_bytes()) ?
    }
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
        nd.send_ipv4(mut pkt, dest_addr) or { success = false }

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
    rlock sock {
        sock_chans = sock.sock_chans
    }
    mut pkt := Packet{}
    println("[IPC Recvmsg] read_chan.len:${sock_chans.read_chan.len}")
    select {
        pkt = <- sock_chans.read_chan {
        }
        200 * time.millisecond {
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