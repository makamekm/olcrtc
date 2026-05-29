package client

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

func (c *Client) handleUDPAssociate(control net.Conn) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = control.Write(replyHostUnreachable())
		return
	}
	defer func() { _ = udpConn.Close() }()

	local := udpConn.LocalAddr().(*net.UDPAddr)
	if _, err := control.Write(replyUDPAssociate(local.Port)); err != nil {
		return
	}

	closed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		close(closed)
		_ = udpConn.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-closed:
			return
		default:
		}
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buf[:n]...)
		go c.relayUDPDatagram(udpConn, clientAddr, packet)
	}
}

func (c *Client) relayUDPDatagram(udpConn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte) {
	targetAddr, targetPort, payload, err := parseSocksUDPDatagram(packet)
	if err != nil || len(payload) == 0 {
		return
	}

	if targetPort != 53 {
		return
	}
	if isBlockedEgressIPv4Address(targetAddr) {
		logger.Debugf("udp DNS target %s:%d rewritten to 1.1.1.1:53", targetAddr, targetPort)
		targetAddr = "1.1.1.1"
	} else if isBlockedEgressHostname(targetAddr) {
		logger.Debugf("udp DNS target %s:%d blocked locally", targetAddr, targetPort)
		return
	}

	c.sessMu.RLock()
	sess := c.session
	c.sessMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return
	}

	stream, err := sess.OpenStream()
	if err != nil {
		logger.Warnf("OpenStream UDP failed: %v", err)
		return
	}
	defer func() { _ = stream.Close() }()

	logger.Debugf("sid=%d udp tunnel to %s:%d", stream.ID(), targetAddr, targetPort)
	if err := c.sendUDPRequest(stream, targetAddr, targetPort); err != nil {
		logger.Warnf("sid=%d udp connect failed: %v", stream.ID(), err)
		return
	}
	_ = stream.SetDeadline(time.Now().Add(6 * time.Second))
	logger.Debugf("sid=%d udp send %s:%d bytes=%d", stream.ID(), targetAddr, targetPort, len(payload))
	if err := writeLengthPrefixedDatagram(stream, payload); err != nil {
		logger.Warnf("sid=%d udp payload write failed: %v", stream.ID(), err)
		return
	}

	response, err := readLengthPrefixedDatagram(stream, 4096)
	if err != nil || len(response) == 0 {
		logger.Warnf("sid=%d udp response read failed: bytes=%d err=%v", stream.ID(), len(response), err)
		return
	}
	logger.Debugf("sid=%d udp recv %s:%d bytes=%d", stream.ID(), targetAddr, targetPort, len(response))
	_, _ = udpConn.WriteToUDP(buildSocksUDPDatagram(targetAddr, targetPort, response), clientAddr)
}

func (c *Client) sendUDPRequest(stream net.Conn, targetAddr string, targetPort int) error {
	connectReq, err := json.Marshal(map[string]any{
		"cmd":      "udp",
		"clientId": c.clientID,
		"addr":     targetAddr,
		"port":     targetPort,
	})
	if err != nil {
		return fmt.Errorf("marshal udp req: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Write(connectReq); err != nil {
		return fmt.Errorf("write udp req: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})

	ack := make([]byte, 1)
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = io.ReadFull(stream, ack)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("%w (read_err=%v ack=%v)", ErrRemoteNotReady, err, ack)
	}
	if ack[0] != 0x00 {
		return fmt.Errorf("%w: remote rejected target (ack=%d)", ErrRemoteNotReady, ack[0])
	}
	return nil
}

func parseSocksUDPDatagram(packet []byte) (string, int, []byte, error) {
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, nil, ErrUnsupportedSOCKSCommand
	}
	offset := 4
	var addr string
	switch packet[3] {
	case 1:
		if len(packet) < offset+4+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		addr = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 3:
		if len(packet) < offset+1 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		length := int(packet[offset])
		offset++
		if len(packet) < offset+length+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		addr = string(packet[offset : offset+length])
		offset += length
	default:
		return "", 0, nil, ErrUnsupportedAddressType
	}
	port := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	return addr, port, packet[offset:], nil
}

func buildSocksUDPDatagram(addr string, port int, payload []byte) []byte {
	ip := net.ParseIP(addr).To4()
	packet := make([]byte, 0, 10+len(addr)+len(payload))
	packet = append(packet, 0, 0, 0)
	if ip != nil {
		packet = append(packet, 1)
		packet = append(packet, ip...)
	} else {
		if len(addr) > 255 {
			addr = addr[:255]
		}
		packet = append(packet, 3, byte(len(addr)))
		packet = append(packet, addr...)
	}
	packet = append(packet, byte(port>>8), byte(port))
	packet = append(packet, payload...)
	return packet
}

func replyUDPAssociate(port int) []byte {
	return []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
}
