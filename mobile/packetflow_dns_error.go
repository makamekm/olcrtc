package mobile

import "encoding/binary"

func buildLocalDNSNoDataResponse(packet []byte) ([]byte, bool) {
	query, qtype, ok := dnsQuestionFromIPv4UDP(packet)
	if !ok {
		return nil, false
	}
	switch qtype {
	case 28: // AAAA: IPv4-only tunnel, avoid IPv6 DNS-over-carrier stalls.
		return buildDNSResponseWithPayload(packet, buildDNSNoDataPayload(query))
	case 64, 65: // SVCB/HTTPS: force classic A/IPv4 TCP path; avoids h3/ECH/alt endpoint choices unsupported by this tunnel.
		return buildDNSResponseWithPayload(packet, buildDNSNoDataPayload(query))
	default:
		return nil, false
	}
}

func buildDNSNoDataPayload(query []byte) []byte {
	payload := append([]byte(nil), query...)
	if len(payload) < 12 {
		return payload
	}
	payload[2] |= 0x80 // QR=response, preserve RD.
	payload[3] = (payload[3] & 0xf0) | 0x00
	binary.BigEndian.PutUint16(payload[6:8], 0)
	binary.BigEndian.PutUint16(payload[8:10], 0)
	binary.BigEndian.PutUint16(payload[10:12], 0)
	return payload
}

func dnsQuestionFromIPv4UDP(packet []byte) ([]byte, uint16, bool) {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil, 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 || packet[9] != 17 {
		return nil, 0, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen <= 0 || totalLen > len(packet) {
		totalLen = len(packet)
	}
	udp := packet[ihl:totalLen]
	if len(udp) < 20 || binary.BigEndian.Uint16(udp[2:4]) != 53 {
		return nil, 0, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 20 || len(udp) < udpLen {
		return nil, 0, false
	}
	query := udp[8:udpLen]
	if len(query) < 12 {
		return nil, 0, false
	}
	offset := 12
	for offset < len(query) {
		labelLen := int(query[offset])
		offset++
		if labelLen == 0 {
			break
		}
		if labelLen&0xc0 != 0 || offset+labelLen > len(query) {
			return nil, 0, false
		}
		offset += labelLen
	}
	if offset+4 > len(query) {
		return nil, 0, false
	}
	return query, binary.BigEndian.Uint16(query[offset : offset+2]), true
}

func buildDNSResponseWithPayload(packet []byte, payload []byte) ([]byte, bool) {
	if len(packet) < 28 || packet[0]>>4 != 4 || len(payload) < 12 {
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
	if len(udp) < 8 {
		return nil, false
	}
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
