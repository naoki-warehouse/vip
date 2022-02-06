module main

import os

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

fn C.ioctl(fd int, request u64, arg voidptr) int

// const ifname_size = C.IFNAMSIZ
const ifname_size = 16

struct C.ifreq {
mut:
	ifr_name  [ifname_size]char
	ifr_flags u16
}

fn tap_alloc(tun_dev_name string) ?os.File {
	mut f := os.File{}
	mut ifr := C.ifreq{}
	f = os.open_file('/dev/net/tun', 'r+') ?

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
		return error('falied to ioctl')
	}

	return f
}
