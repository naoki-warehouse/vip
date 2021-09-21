module main

struct HdrNone {}

fn (hn HdrNone) len() int {
    return 0
}

type L3Hdr = HdrNone | ArpHdr | IPv4Hdr
type L4Hdr = HdrNone | IcmpHdr

struct Packet {
mut:
    l2_hdr EthHdr
    l3_hdr L3Hdr
    l4_hdr L4Hdr
    payload []byte
}
