module main

import net.unix

struct IpcMsg {
	opcode u16
    pid i64
    msg []byte
}

enum IpcOpcode {
    socket = 0x1
}

struct Socket {
mut:
    pid int
    fd int
    sock_type int
    protocol u8
    port u16
    sock_chans SocketChans
    stream unix.StreamConn
}

struct SocketChans {

}

fn new_socket_chans() SocketChans {
    return SocketChans {

    }
}

fn (nd NetDevice) handle_control_usock(usock_path string) {
    mut l := unix.listen_stream(usock_path) or { panic(err) }
    for {
        mut new_conn := l.accept() or { continue }
        sock := Socket {
            sock_chans : new_socket_chans()
            stream : new_conn
        }
        println("new conn")
        nd.sock_chan <- sock
    }
}

fn (sock Socket) handle_data(nd &NetDevice) {
    mut sk := sock.stream
    for {
        mut buf := []byte{len: 8192, init: 0}
        count := sk.read(mut buf) or {
            println('Server: connection drppped')
            return
        }

        println("recv size${count}")
    }
}