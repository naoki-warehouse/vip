module main

struct IcmpHdrBase {
    len int = 4
mut:
    icmp_type u8
    code u8
    chksum u16
}

struct IcmpHdrEcho {
    IcmpHdrBase
    len int = 8
mut:
    id u16
    seq_num u16
}

type IcmpHdrType = IcmpHdrBase | IcmpHdrEcho

struct  IcmpHdr {
    hdr IcmpHdrType
}

enum IcmpType {
    echo_reply = 0
    echo_request = 8
}

fn parse_icmp_hdr(buf []byte) ?IcmpHdr {
    assert buf.len >= 4
    base := IcmpHdrBase {
        icmp_type : buf[0]
        code : buf[1]
        chksum : be16(buf[2..4])
    }

    if base.icmp_type == byte(IcmpType.echo_reply)  ||
       base.icmp_type == byte(IcmpType.echo_request) {
           assert buf.len >= 8
            return IcmpHdr {
                hdr: IcmpHdrEcho {
                    IcmpHdrBase: base
                    id : be16(buf[4..6])
                    seq_num : be16(buf[6..8])
                }
            }
    }

    return IcmpHdr {
        hdr: base
    }
}

fn (ih IcmpHdrBase) to_string() string {
    mut s := "Type:$ih.icmp_type "
    s += "Code:$ih.code "
    s += "Checksum:0x${ih.chksum}"

    return s
}

fn (ih IcmpHdrEcho) to_string() string {
    mut s := ih.IcmpHdrBase.to_string() + " "
    s += "ID:0x${ih.id:04X} "
    s += "SeqNum:0x${ih.seq_num:04X}"

    return s
}

fn (ih IcmpHdrBase) to_bytes() []byte {
    mut buf := []byte{len:4}
    buf[0] = ih.icmp_type
    buf[1] = ih.code
    copy(buf[2..4], be_u16_to_bytes(ih.chksum))

    return buf[0..]
}

fn (ih IcmpHdrEcho) to_bytes() []byte {
    mut buf_base := ih.IcmpHdrBase.to_bytes()
    mut buf := []byte{len:4}
    copy(buf[0..2], be_u16_to_bytes(ih.id))
    copy(buf[2..4], be_u16_to_bytes(ih.seq_num))
    buf_base << buf

    return buf_base
}

fn (ih IcmpHdr) to_bytes() []byte {
    match ih.hdr {
        IcmpHdrBase {
            return ih.hdr.to_bytes()
        }
        IcmpHdrEcho {
            return ih.hdr.to_bytes()
        }
    }
}

fn (ih IcmpHdr) to_string() string {
    match ih.hdr {
        IcmpHdrBase {
            return ih.hdr.to_string()
        }
        IcmpHdrEcho {
            return ih.hdr.to_string()
        }
    }
}

fn (ih IcmpHdr) len() int {
    match ih.hdr {
        IcmpHdrBase {
            return ih.hdr.len
        }
        IcmpHdrEcho {
            return ih.hdr.len
        }
    }
}

fn calc_chksum(buf []byte) u16 {
    mut chksum := u32(0)
    for i := 0; i < buf.len; i += 2 {
        if i + 1 >= buf.len {
            chksum += buf[i] << 8
        } else {
            chksum += (buf[i] << 8) | buf[i+1]
        }

        if chksum > 0xFFFF {
            chksum = (chksum & 0xFFFF) + 1
        }
    }

    return u16((~chksum) & 0xFFFF)
}


