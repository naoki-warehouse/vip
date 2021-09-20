module main

type L3Hdr = ArpHdr | IPv4Hdr

struct Packet {
	l2_hdr EthHdr
    l3_hdr L3Hdr
}
