module main

fn le_bytes_to_u16(buf []byte) ?u16 {
	assert buf.len == 2
	return u16(buf[0]) | u16(buf[1]) << 8
}

fn le_bytes_to_u32(buf []byte) ?u32 {
	assert buf.len == 4
	return u32(buf[0]) | u32(buf[1]) << 8 | u32(buf[2]) << 16 | u32(buf[3]) << 24
}

fn le_bytes_to_u64(buf []byte) ?u64 {
	assert buf.len == 8
	mut tmp := u64(0)
	tmp |= u64(buf[0]) | u64(buf[1]) << 8 | u64(buf[2]) << 16 | u64(buf[3]) << 24
	tmp |= u64(buf[4]) << 32 | u64(buf[5]) << 40 | u64(buf[6]) << 48 | u64(buf[7]) << 56
	return tmp
}

fn le_u16_to_bytes(val u16) []byte {
	mut buf := []byte{len: 2}
	buf[0] = byte(val)
	buf[1] = byte(val >> 8)
	return buf
}

fn le_u32_to_bytes(val u32) []byte {
	mut buf := []byte{len: 4}
	buf[0] = byte(val)
	buf[1] = byte(val >> 8)
	buf[2] = byte(val >> 16)
	buf[3] = byte(val >> 24)
	return buf
}

fn le_u64_to_bytes(val u64) []byte {
	mut buf := []byte{len: 8}
	buf[0] = byte(val)
	buf[1] = byte(val >> 8)
	buf[2] = byte(val >> 16)
	buf[3] = byte(val >> 24)
	buf[4] = byte(val >> 32)
	buf[5] = byte(val >> 40)
	buf[6] = byte(val >> 48)
	buf[7] = byte(val >> 56)
	return buf
}

fn be_u16_to_bytes(val u16) []byte {
	mut buf := []byte{len: 2}
	buf[0] = byte(val >> 8)
	buf[1] = byte(val)

	return buf
}

fn be_u32_to_bytes(val u32) []byte {
	mut buf := []byte{len: 4}
	buf[0] = byte(val >> 24)
	buf[1] = byte(val >> 16)
	buf[2] = byte(val >> 8)
	buf[3] = byte(val)

	return buf
}

fn be_bytes_to_u32(buf []byte) ?u32 {
	assert buf.len == 4
	mut val := u32(0)
	val |= u32(buf[0]) << 24
	val |= u32(buf[1]) << 16
	val |= u32(buf[2]) << 8
	val |= u32(buf[3]) << 0
	return val
}

fn calc_chksum(buf []byte) u16 {
	mut chksum := u32(0)
	for i := 0; i < buf.len; i += 2 {
		if i + 1 >= buf.len {
			chksum += u16(buf[i]) << 8
		} else {
			chksum += (u16(buf[i]) << 8) | buf[i + 1]
		}

		if chksum > 0xFFFF {
			chksum = (chksum & 0xFFFF) + 1
		}
	}

	return u16((~chksum) & 0xFFFF)
}

fn calc_pseudo_header(src_addr &IpAddress, dst_addr &IpAddress, protocol u8, length u16) u16 {
	mut buf := []byte{len: 12}
	copy(buf[0..], src_addr.addr[0..])
	copy(buf[4..], dst_addr.addr[0..])
	buf[8] = 0
	buf[9] = protocol
	copy(buf[10..], be_u16_to_bytes(length))
	chksum := calc_chksum(buf[0..])
	return ~chksum
}
