package mobile

import (
	"encoding/binary"
	"net"
)

func isSyntheticDNSAnswer(answer []byte) bool {
	for _, ip := range packetFlowDNSAnswerIPv4s(answer) {
		if isSyntheticIPv4(ip) {
			return true
		}
	}
	return false
}

func isSyntheticIPv4(ip net.IP) bool {
	v4 := ip.To4()
	return len(v4) == 4 && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

func packetFlowDNSAnswerIPv4s(answer []byte) []net.IP {
	if len(answer) < 12 {
		return nil
	}
	questionCount := int(binary.BigEndian.Uint16(answer[4:6]))
	answerCount := int(binary.BigEndian.Uint16(answer[6:8]))
	offset := 12
	for i := 0; i < questionCount; i++ {
		var ok bool
		offset, ok = skipDNSName(answer, offset)
		if !ok || offset+4 > len(answer) {
			return nil
		}
		offset += 4
	}

	ips := make([]net.IP, 0, answerCount)
	for i := 0; i < answerCount; i++ {
		var ok bool
		offset, ok = skipDNSName(answer, offset)
		if !ok || offset+10 > len(answer) {
			return ips
		}
		rrType := binary.BigEndian.Uint16(answer[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(answer[offset+8 : offset+10]))
		rdata := offset + 10
		if rdata+rdLen > len(answer) {
			return ips
		}
		if rrType == 1 && rdLen == 4 {
			ips = append(ips, net.IPv4(answer[rdata], answer[rdata+1], answer[rdata+2], answer[rdata+3]))
		}
		offset = rdata + rdLen
	}
	return ips
}

func skipDNSName(packet []byte, offset int) (int, bool) {
	for jumps := 0; ; jumps++ {
		if offset >= len(packet) || jumps > 128 {
			return 0, false
		}
		length := packet[offset]
		switch {
		case length == 0:
			return offset + 1, true
		case length&0xc0 == 0xc0:
			if offset+2 > len(packet) {
				return 0, false
			}
			return offset + 2, true
		case length&0xc0 != 0:
			return 0, false
		default:
			offset += int(length) + 1
		}
	}
}
