package client

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

const udpRelayIdleTimeout = 30 * time.Second
const udpRelayMaxClientAddrs = 8

var udpRelayStats udpRelayDebugStats

type udpRelayDebugStats struct {
	opens      atomic.Uint64
	openFailed atomic.Uint64
	sent       atomic.Uint64
	sendFailed atomic.Uint64
	received   atomic.Uint64
	recvEnded  atomic.Uint64
}

func recordUDPRelayOpen()       { udpRelayStats.opens.Add(1) }
func recordUDPRelayOpenFailed() { udpRelayStats.openFailed.Add(1) }
func recordUDPRelaySent()       { udpRelayStats.sent.Add(1) }
func recordUDPRelaySendFailed() { udpRelayStats.sendFailed.Add(1) }
func recordUDPRelayReceived()   { udpRelayStats.received.Add(1) }
func recordUDPRelayRecvEnded()  { udpRelayStats.recvEnded.Add(1) }

func UDPRelayDebugStats() string {
	return fmt.Sprintf("udp_relay_open=%d udp_relay_open_failed=%d udp_relay_sent=%d udp_relay_send_failed=%d udp_relay_received=%d udp_relay_recv_ended=%d", udpRelayStats.opens.Load(), udpRelayStats.openFailed.Load(), udpRelayStats.sent.Load(), udpRelayStats.sendFailed.Load(), udpRelayStats.received.Load(), udpRelayStats.recvEnded.Load())
}

type udpRelaySession struct {
	key         string
	targetAddr  string
	targetPort  int
	clientAddrs map[string]*net.UDPAddr
	clientOrder []string
	udpConn     *net.UDPConn
	stream      net.Conn
	mu          sync.Mutex
	closeOnce   sync.Once
	closed      chan struct{}
	onClose     func(string)
}

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

	var relaysMu sync.Mutex
	relays := map[string]*udpRelaySession{}
	closeRelay := func(key string) {
		relaysMu.Lock()
		delete(relays, key)
		relaysMu.Unlock()
	}
	defer func() {
		relaysMu.Lock()
		active := make([]*udpRelaySession, 0, len(relays))
		for _, relay := range relays {
			active = append(active, relay)
		}
		relays = map[string]*udpRelaySession{}
		relaysMu.Unlock()
		for _, relay := range active {
			relay.Close()
		}
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
		targetAddr, targetPort, payload, err := parseSocksUDPDatagram(packet)
		if err != nil || len(payload) == 0 {
			continue
		}
		targetAddr, ok := normalizeUDPTarget(targetAddr, targetPort)
		if !ok {
			continue
		}
		key := udpRelayKey(targetAddr, targetPort)

		relaysMu.Lock()
		relay := relays[key]
		if relay == nil || relay.IsClosed() {
			relay, err = c.openUDPRelay(udpConn, clientAddr, key, targetAddr, targetPort, closeRelay)
			if err != nil {
				recordUDPRelayOpenFailed()
				logger.Warnf("udp relay open %s:%d failed: %v", targetAddr, targetPort, err)
				relaysMu.Unlock()
				continue
			}
			relays[key] = relay
		} else {
			relay.UpdateClientAddr(clientAddr)
		}
		relaysMu.Unlock()

		if err := relay.Send(payload); err != nil {
			recordUDPRelaySendFailed()
			logger.Warnf("udp relay send %s failed: %v", key, err)
			relay.Close()
		}
	}
}

func normalizeUDPTarget(targetAddr string, targetPort int) (string, bool) {
	if targetPort == 53 {
		if isBlockedEgressIPv4Address(targetAddr) {
			logger.Debugf("udp DNS target %s:%d rewritten to 1.1.1.1:53", targetAddr, targetPort)
			return "1.1.1.1", true
		}
		if isBlockedEgressHostname(targetAddr) {
			logger.Debugf("udp DNS target %s:%d blocked locally", targetAddr, targetPort)
			return "", false
		}
		return targetAddr, true
	}
	if isBlockedEgressIPv4Address(targetAddr) || isBlockedEgressHostname(targetAddr) {
		logger.Debugf("udp target %s:%d blocked locally", targetAddr, targetPort)
		return "", false
	}
	return targetAddr, true
}

func (c *Client) openUDPRelay(udpConn *net.UDPConn, clientAddr *net.UDPAddr, key, targetAddr string, targetPort int, onClose func(string)) (*udpRelaySession, error) {
	c.sessMu.RLock()
	sess := c.session
	c.sessMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return nil, ErrRemoteNotReady
	}

	stream, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := c.sendUDPRequest(stream, targetAddr, targetPort); err != nil {
		_ = stream.Close()
		return nil, err
	}
	relay := &udpRelaySession{
		key:         key,
		targetAddr:  targetAddr,
		targetPort:  targetPort,
		clientAddrs: map[string]*net.UDPAddr{},
		udpConn:     udpConn,
		stream:      stream,
		closed:      make(chan struct{}),
		onClose:     onClose,
	}
	relay.UpdateClientAddr(clientAddr)
	go relay.ReadLoop()
	recordUDPRelayOpen()
	logger.Debugf("udp relay open %s target=%s:%d", key, targetAddr, targetPort)
	return relay, nil
}

func (r *udpRelaySession) Send(payload []byte) error {
	select {
	case <-r.closed:
		return net.ErrClosed
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stream == nil {
		return net.ErrClosed
	}
	_ = r.stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	logger.Debugf("udp relay send %s bytes=%d", r.key, len(payload))
	err := writeLengthPrefixedDatagram(r.stream, payload)
	if err == nil {
		recordUDPRelaySent()
	}
	_ = r.stream.SetWriteDeadline(time.Time{})
	return err
}

func (r *udpRelaySession) UpdateClientAddr(clientAddr *net.UDPAddr) {
	if clientAddr == nil {
		return
	}
	key := clientAddr.String()
	r.mu.Lock()
	if _, exists := r.clientAddrs[key]; !exists {
		r.clientOrder = append(r.clientOrder, key)
	}
	r.clientAddrs[key] = clientAddr
	for len(r.clientOrder) > udpRelayMaxClientAddrs {
		oldest := r.clientOrder[0]
		r.clientOrder = r.clientOrder[1:]
		delete(r.clientAddrs, oldest)
	}
	r.mu.Unlock()
}

func (r *udpRelaySession) ReadLoop() {
	defer r.Close()
	for {
		_ = r.stream.SetReadDeadline(time.Now().Add(udpRelayIdleTimeout))
		response, err := readLengthPrefixedDatagram(r.stream, 65535)
		if err != nil || len(response) == 0 {
			recordUDPRelayRecvEnded()
			if err != nil && !errors.Is(err, io.EOF) {
				logger.Debugf("udp relay recv %s ended: bytes=%d err=%v", r.key, len(response), err)
			}
			return
		}
		recordUDPRelayReceived()
		logger.Debugf("udp relay recv %s bytes=%d", r.key, len(response))
		packet := buildSocksUDPDatagram(r.targetAddr, r.targetPort, response)
		r.mu.Lock()
		clientAddrs := make([]*net.UDPAddr, 0, len(r.clientOrder))
		for i := len(r.clientOrder) - 1; i >= 0; i-- {
			if clientAddr := r.clientAddrs[r.clientOrder[i]]; clientAddr != nil {
				clientAddrs = append(clientAddrs, clientAddr)
			}
		}
		r.mu.Unlock()
		for _, clientAddr := range clientAddrs {
			_, _ = r.udpConn.WriteToUDP(packet, clientAddr)
		}
	}
}

func (r *udpRelaySession) Close() {
	r.closeOnce.Do(func() {
		close(r.closed)
		if r.stream != nil {
			_ = r.stream.Close()
		}
		if r.onClose != nil {
			r.onClose(r.key)
		}
	})
}

func (r *udpRelaySession) IsClosed() bool {
	select {
	case <-r.closed:
		return true
	default:
		return false
	}
}

func udpRelayKey(targetAddr string, targetPort int) string {
	return net.JoinHostPort(targetAddr, fmt.Sprint(targetPort))
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
