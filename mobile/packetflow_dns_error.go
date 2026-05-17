package mobile

import "encoding/binary"

func buildDNSFailureResponse(packet []byte) ([]byte, bool) {
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
	udp := packet[ihl:totalLen]
	if len(udp) < 20 || binary.BigEndian.Uint16(udp[2:4]) != 53 {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 20 || len(udp) < udpLen {
		return nil, false
	}
	query := udp[8:udpLen]
	if len(query) < 12 {
		return nil, false
	}

	payload := append([]byte(nil), query...)
	payload[2] |= 0x80
	payload[3] = (payload[3] & 0xf0) | 0x02
	binary.BigEndian.PutUint16(payload[6:8], 0)
	binary.BigEndian.PutUint16(payload[8:10], 0)
	binary.BigEndian.PutUint16(payload[10:12], 0)

	respLen := ihl + 8 + len(payload)
	resp := make([]byte, respLen)
	copy(resp[:ihl], packet[:ihl])
	copy(resp[12:16], packet[16:20])
	copy(resp[16:20], packet[12:16])
	binary.BigEndian.PutUint16(resp[2:4], uint16(respLen))
	binary.BigEndian.PutUint16(resp[4:6], 0)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	resp[8] = 64
	resp[10], resp[11] = 0, 0
	binary.BigEndian.PutUint16(resp[10:12], ipv4Checksum(resp[:ihl]))

	outUDP := resp[ihl:]
	binary.BigEndian.PutUint16(outUDP[0:2], 53)
	binary.BigEndian.PutUint16(outUDP[2:4], binary.BigEndian.Uint16(udp[0:2]))
	binary.BigEndian.PutUint16(outUDP[4:6], uint16(8+len(payload)))
	copy(outUDP[8:], payload)
	binary.BigEndian.PutUint16(outUDP[6:8], 0)
	binary.BigEndian.PutUint16(outUDP[6:8], udpChecksum(resp[12:16], resp[16:20], outUDP))
	return resp, true
}
