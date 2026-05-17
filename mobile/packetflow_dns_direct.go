package mobile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func resolveDNSOverTCPDirect(query []byte, dnsServer string) ([]byte, error) {
	answer, err := resolveDNSOverUDPDirect(query, dnsServer)
	if err == nil && !isDNSResponseTruncated(answer) {
		return answer, nil
	}
	fallbackAnswer, fallbackErr := resolveDNSOverTCPDirectOnce(query, dnsServer)
	if fallbackErr == nil {
		return fallbackAnswer, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fallbackErr
}

func resolveDNSOverUDPDirect(query []byte, dnsServer string) ([]byte, error) {
	if len(query) > 65535 {
		return nil, fmt.Errorf("dns query too large")
	}
	conn, err := net.DialTimeout("udp", dnsServer, 800*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	answer := make([]byte, 65535)
	n, err := conn.Read(answer)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.New("empty dns udp answer")
	}
	return answer[:n], nil
}

func resolveDNSOverTCPDirectOnce(query []byte, dnsServer string) ([]byte, error) {
	if len(query) > 65535 {
		return nil, fmt.Errorf("dns query too large")
	}
	conn, err := net.DialTimeout("tcp", dnsServer, 800*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
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

func isDNSResponseTruncated(answer []byte) bool {
	return len(answer) >= 3 && answer[2]&0x02 != 0
}
