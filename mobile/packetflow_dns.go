package mobile

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

const packetFlowDNSServer = "192.168.0.1:53"

func (rw *packetFlowReadWriter) tryHandleDNS(packet []byte) bool {
	if !isIPv4UDP53(packet) {
		return false
	}
	atomic.AddUint64(&rw.dnsSeen, 1)
	packetCopy := append([]byte(nil), packet...)
	go func() {
		resp, ok := buildDNSResponseViaTCP(packetCopy, rw.socksHost, rw.socksPort)
		if !ok || len(resp) == 0 {
			atomic.AddUint64(&rw.dnsMiss, 1)
			if failure, built := buildDNSFailureResponse(packetCopy); built {
				_ = rw.Respond(failure)
			}
			return
		}
		atomic.AddUint64(&rw.dnsAnswered, 1)
		_ = rw.Respond(resp)
	}()
	return true
}

func isIPv4UDP(packet []byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	return ihl >= 20 && len(packet) >= ihl+8 && packet[9] == 17
}

func isIPv4UDP53(packet []byte) bool {
	if !isIPv4UDP(packet) {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 || packet[9] != 17 {
		return false
	}
	return binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) == 53
}

func buildDNSResponseViaTCP(packet []byte, socksHost string, socksPort int) ([]byte, bool) {
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
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	if dstPort != 53 {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		return nil, false
	}
	query := append([]byte(nil), udp[8:udpLen]...)
	answer, err := resolveDNSOverTCPViaSocks(query, socksHost, socksPort)
	if err != nil || len(answer) == 0 {
		return nil, false
	}

	payloadLen := len(answer)
	respLen := ihl + 8 + payloadLen
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
	binary.BigEndian.PutUint16(outUDP[0:2], dstPort)
	binary.BigEndian.PutUint16(outUDP[2:4], srcPort)
	binary.BigEndian.PutUint16(outUDP[4:6], uint16(8+payloadLen))
	copy(outUDP[8:], answer)
	binary.BigEndian.PutUint16(outUDP[6:8], 0)
	binary.BigEndian.PutUint16(outUDP[6:8], udpChecksum(resp[12:16], resp[16:20], outUDP))
	return resp, true
}

func resolveDNSOverTCPViaSocks(query []byte, socksHost string, socksPort int) ([]byte, error) {
	if cached, ok := getCachedDNSAnswer(query); ok {
		return cached, nil
	}
	var lastErr error
	answer, err := resolveDNSOverTCPDirect(query, packetFlowDNSServer)
	if err == nil && len(answer) > 0 && !isRetryableDNSResponse(answer) {
		putCachedDNSAnswer(query, answer)
		return answer, nil
	}
	lastErr = err
	if err == nil && isRetryableDNSResponse(answer) {
		lastErr = errors.New("retryable dns response from direct resolver")
	}
	for attempt := 0; attempt < 2; attempt++ {
		answer, err = resolveDNSOverTCPViaSocksOnce(query, socksHost, socksPort)
		if err == nil && len(answer) > 0 && !isRetryableDNSResponse(answer) {
			putCachedDNSAnswer(query, answer)
			return answer, nil
		}
		lastErr = err
		if err == nil && isRetryableDNSResponse(answer) {
			lastErr = errors.New("retryable dns response from socks resolver")
		}
	}
	if lastErr == nil {
		lastErr = errors.New("empty dns answer")
	}
	return nil, lastErr
}

func isRetryableDNSResponse(answer []byte) bool {
	if len(answer) < 4 {
		return false
	}
	rcode := answer[3] & 0x0f
	return rcode == 2 || rcode == 5 // SERVFAIL/REFUSED: retry via carrier, never cache.
}

func resolveDNSOverTCPViaSocksOnce(query []byte, socksHost string, socksPort int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(socksHost, strconv.Itoa(socksPort)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5Connect(conn, packetFlowDNSServer); err != nil {
		return nil, err
	}
	if len(query) > 65535 {
		return nil, errors.New("dns query too large")
	}
	prefix := []byte{byte(len(query) >> 8), byte(len(query))}
	if _, err := conn.Write(prefix); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	answerLen := int(binary.BigEndian.Uint16(length[:]))
	if answerLen <= 0 || answerLen > 65535 {
		return nil, fmt.Errorf("invalid dns answer length: %d", answerLen)
	}
	answer := make([]byte, answerLen)
	if _, err := io.ReadFull(conn, answer); err != nil {
		return nil, err
	}
	return answer, nil
}

func socks5Connect(conn net.Conn, target string) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 5 || resp[1] != 0 {
		return fmt.Errorf("socks auth rejected: %v", resp)
	}
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return err
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, 1)
		req = append(req, ip...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp = make([]byte, 10)
	if _, err := io.ReadFull(conn, resp[:4]); err != nil {
		return err
	}
	if resp[0] != 5 || resp[1] != 0 {
		return fmt.Errorf("socks connect rejected: %d", resp[1])
	}
	switch resp[3] {
	case 1:
		_, err = io.ReadFull(conn, resp[:6])
	case 3:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		_, err = io.ReadFull(conn, make([]byte, int(l[0])+2))
	case 4:
		_, err = io.ReadFull(conn, make([]byte, 18))
	default:
		err = fmt.Errorf("unknown socks atyp: %d", resp[3])
	}
	return err
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(src, dst, udp []byte) uint16 {
	var sum uint32
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += uint32(17)
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	v := ^uint16(sum)
	if v == 0 {
		return 0xffff
	}
	return v
}
