package mobile

import "encoding/binary"

func buildIPv4ICMPPortUnreachable(packet []byte) ([]byte, bool) {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 || packet[9] != 17 {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen <= 0 || totalLen > len(packet) {
		totalLen = len(packet)
	}
	quotedLen := min(totalLen, ihl+8)
	respLen := 20 + 8 + quotedLen
	resp := make([]byte, respLen)

	resp[0] = 0x45
	resp[1] = 0
	binary.BigEndian.PutUint16(resp[2:4], uint16(respLen))
	binary.BigEndian.PutUint16(resp[4:6], 0)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	resp[8] = 64
	resp[9] = 1
	copy(resp[12:16], packet[16:20])
	copy(resp[16:20], packet[12:16])
	binary.BigEndian.PutUint16(resp[10:12], ipv4Checksum(resp[:20]))

	icmp := resp[20:]
	icmp[0] = 3
	icmp[1] = 3
	copy(icmp[8:], packet[:quotedLen])
	binary.BigEndian.PutUint16(icmp[2:4], ipv4Checksum(icmp))
	return resp, true
}
