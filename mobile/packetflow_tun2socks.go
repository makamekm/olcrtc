package mobile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var packetFlowTun2Socks = newPacketFlowTun2SocksState()

type packetFlowTun2SocksState struct {
	mu       sync.Mutex
	running  bool
	st       *stack.Stack
	endpoint *iobased.Endpoint
	rw       *packetFlowReadWriter
}

func newPacketFlowTun2SocksState() *packetFlowTun2SocksState {
	return &packetFlowTun2SocksState{}
}

func MobileStartPacketFlowTun2Socks(socksHost string, socksPort int64, mtu int64) (bool, error) {
	packetFlowTun2Socks.mu.Lock()
	defer packetFlowTun2Socks.mu.Unlock()

	if packetFlowTun2Socks.running {
		return true, nil
	}
	clearPacketFlowDNSCache()
	if socksHost == "" {
		socksHost = "127.0.0.1"
	}
	if socksPort <= 0 || socksPort > 65535 {
		return false, fmt.Errorf("invalid SOCKS port: %d", socksPort)
	}
	if mtu <= 0 {
		mtu = 1280
	}

	rw := newPacketFlowReadWriter(int(mtu), socksHost, int(socksPort))
	endpoint, err := iobased.New(rw, uint32(mtu), 0)
	if err != nil {
		return false, fmt.Errorf("create packet-flow endpoint: %w", err)
	}

	socks, err := proxy.NewSocks5(fmt.Sprintf("%s:%d", socksHost, socksPort), "", "")
	if err != nil {
		endpoint.Close()
		return false, fmt.Errorf("create socks proxy: %w", err)
	}
	tunnel.T().SetDialer(socks)

	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     endpoint,
		TransportHandler: tunnel.T(),
	})
	if err != nil {
		endpoint.Close()
		return false, fmt.Errorf("create stack: %w", err)
	}

	packetFlowTun2Socks.rw = rw
	packetFlowTun2Socks.endpoint = endpoint
	packetFlowTun2Socks.st = st
	packetFlowTun2Socks.running = true
	return true, nil
}

func MobileStopPacketFlowTun2Socks() {
	packetFlowTun2Socks.mu.Lock()
	defer packetFlowTun2Socks.mu.Unlock()
	clearPacketFlowDNSCache()
	if packetFlowTun2Socks.rw != nil {
		packetFlowTun2Socks.rw.Close()
	}
	if packetFlowTun2Socks.endpoint != nil {
		packetFlowTun2Socks.endpoint.Close()
	}
	if packetFlowTun2Socks.st != nil {
		packetFlowTun2Socks.st.Close()
		packetFlowTun2Socks.st.Wait()
	}
	packetFlowTun2Socks.rw = nil
	packetFlowTun2Socks.endpoint = nil
	packetFlowTun2Socks.st = nil
	packetFlowTun2Socks.running = false
}

func MobileInjectPacket(packet []byte) (bool, error) {
	packetFlowTun2Socks.mu.Lock()
	rw := packetFlowTun2Socks.rw
	packetFlowTun2Socks.mu.Unlock()
	if rw == nil {
		return false, errors.New("packet-flow tun2socks is not running")
	}
	return true, rw.Inject(packet)
}

func MobileReadPacket(timeoutMillis int64) ([]byte, error) {
	packetFlowTun2Socks.mu.Lock()
	rw := packetFlowTun2Socks.rw
	packetFlowTun2Socks.mu.Unlock()
	if rw == nil {
		return nil, errors.New("packet-flow tun2socks is not running")
	}
	return rw.ReadOutbound(time.Duration(timeoutMillis) * time.Millisecond)
}

const packetFlowUDPICMPRejectBudget = 256

type packetFlowReadWriter struct {
	inbound             chan []byte
	outbound            chan []byte
	closed              chan struct{}
	once                sync.Once
	mtu                 int
	socksHost           string
	socksPort           int
	dnsServer           string
	udpRejectMu         sync.Mutex
	udpReject           map[string]time.Time
	udpRejectICMPBudget uint64
	udpICMPRejected     uint64
	inPackets           uint64
	outPackets          uint64
	udpForwarded        uint64
	dnsSeen             uint64
	dnsAnswered         uint64
	dnsMiss             uint64
	dnsA                uint64
	dnsAAAA             uint64
	dnsHTTPS            uint64
	dnsSVCB             uint64
	dnsOther            uint64
	dnsAWithIPv4        uint64
	dnsAEmpty           uint64
	dnsDirectUDP        uint64
	dnsDirectTCP        uint64
	dnsSocks            uint64
	dnsCache            uint64
	udpDropped          uint64
}

func newPacketFlowReadWriter(mtu int, socksHost string, socksPort int) *packetFlowReadWriter {
	dnsServer := currentPacketFlowDNSServer()
	return &packetFlowReadWriter{
		inbound:   make(chan []byte, 2048),
		outbound:  make(chan []byte, 2048),
		closed:    make(chan struct{}),
		mtu:       mtu,
		socksHost: socksHost,
		socksPort: socksPort,
		dnsServer: dnsServer,
		udpReject: map[string]time.Time{},
	}
}

func (rw *packetFlowReadWriter) Read(dst []byte) (int, error) {
	select {
	case <-rw.closed:
		return 0, io.ErrClosedPipe
	case packet := <-rw.inbound:
		if len(packet) == 0 || len(packet) > rw.mtu {
			return 0, nil
		}
		return copy(dst, packet), nil
	}
}

func (rw *packetFlowReadWriter) Write(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}
	copyPacket := append([]byte(nil), packet...)
	select {
	case <-rw.closed:
		return 0, io.ErrClosedPipe
	case rw.outbound <- copyPacket:
		return len(packet), nil
	default:
		return 0, errors.New("packet-flow outbound queue is full")
	}
}

func (rw *packetFlowReadWriter) Inject(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	if rw.tryHandleDNS(packet) {
		return nil
	}
	if isIPv4UDP(packet) && !rw.shouldForwardUDP(packet) {
		// DNS is answered above. Non-DNS UDP is intentionally rejected in the
		// iOS packet-flow bridge. Forwarding QUIC/media UDP/443 through SOCKS5
		// UDP ASSOCIATE looks like activity in PacketTunnel counters but leaves
		// real YouTube stuck on feed/player loading on current RUPN transports.
		// YouTube opens many UDP/443 flows. A tiny global ICMP budget is not
		// enough to push the app/browser off QUIC, so allow a bounded burst of
		// first-flow ICMP rejects and then drop/count only to avoid an unbounded
		// PacketTunnel outbound storm.
		atomic.AddUint64(&rw.udpDropped, 1)
		if rw.shouldRejectUDP(packet) && atomic.AddUint64(&rw.udpRejectICMPBudget, 1) <= packetFlowUDPICMPRejectBudget {
			if resp, ok := buildIPv4ICMPPortUnreachable(packet); ok {
				if rw.Respond(resp) == nil {
					atomic.AddUint64(&rw.udpICMPRejected, 1)
				}
			}
		}
		return nil
	}
	if isIPv4UDP(packet) {
		atomic.AddUint64(&rw.udpForwarded, 1)
	}
	atomic.AddUint64(&rw.inPackets, 1)
	copyPacket := append([]byte(nil), packet...)
	select {
	case <-rw.closed:
		return io.ErrClosedPipe
	case rw.inbound <- copyPacket:
		return nil
	default:
		return errors.New("packet-flow inbound queue is full")
	}
}

func (rw *packetFlowReadWriter) Respond(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	copyPacket := append([]byte(nil), packet...)
	select {
	case <-rw.closed:
		return io.ErrClosedPipe
	case rw.outbound <- copyPacket:
		return nil
	default:
		return errors.New("packet-flow outbound queue is full")
	}
}

func (rw *packetFlowReadWriter) ReadOutbound(timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-rw.closed:
		return nil, io.ErrClosedPipe
	case packet := <-rw.outbound:
		atomic.AddUint64(&rw.outPackets, 1)
		return packet, nil
	case <-timer.C:
		return nil, nil
	}
}

func (rw *packetFlowReadWriter) Close() {
	rw.once.Do(func() { close(rw.closed) })
}

func (rw *packetFlowReadWriter) countDNSQuestionType(packet []byte) {
	_, qtype, ok := dnsQuestionFromIPv4UDP(packet)
	if !ok {
		atomic.AddUint64(&rw.dnsOther, 1)
		return
	}
	switch qtype {
	case 1:
		atomic.AddUint64(&rw.dnsA, 1)
	case 28:
		atomic.AddUint64(&rw.dnsAAAA, 1)
	case 64:
		atomic.AddUint64(&rw.dnsSVCB, 1)
	case 65:
		atomic.AddUint64(&rw.dnsHTTPS, 1)
	default:
		atomic.AddUint64(&rw.dnsOther, 1)
	}
}

func (rw *packetFlowReadWriter) countDNSAnswer(queryPacket []byte, responsePacket []byte) {
	_, qtype, ok := dnsQuestionFromIPv4UDP(queryPacket)
	if !ok || qtype != 1 {
		return
	}
	payload, ok := dnsPayloadFromIPv4UDP(responsePacket)
	if !ok || len(packetFlowDNSAnswerIPv4s(payload)) == 0 {
		atomic.AddUint64(&rw.dnsAEmpty, 1)
		return
	}
	atomic.AddUint64(&rw.dnsAWithIPv4, 1)
}

func (rw *packetFlowReadWriter) countDNSAnswerSource(source packetFlowDNSAnswerSource) {
	switch source {
	case packetFlowDNSAnswerDirectUDP:
		atomic.AddUint64(&rw.dnsDirectUDP, 1)
	case packetFlowDNSAnswerDirectTCP:
		atomic.AddUint64(&rw.dnsDirectTCP, 1)
	case packetFlowDNSAnswerSocks:
		atomic.AddUint64(&rw.dnsSocks, 1)
	case packetFlowDNSAnswerCache:
		atomic.AddUint64(&rw.dnsCache, 1)
	}
}

func dnsPayloadFromIPv4UDP(packet []byte) ([]byte, bool) {
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
	if len(udp) < 8 {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		return nil, false
	}
	return udp[8:udpLen], true
}

func (rw *packetFlowReadWriter) shouldForwardUDP(packet []byte) bool {
	return false
}

func (rw *packetFlowReadWriter) shouldRejectUDP(packet []byte) bool {
	key, ok := ipv4UDPFlowKey(packet)
	if !ok {
		return false
	}
	now := time.Now()
	rw.udpRejectMu.Lock()
	defer rw.udpRejectMu.Unlock()
	if last, exists := rw.udpReject[key]; exists && now.Sub(last) < 5*time.Second {
		return false
	}
	if len(rw.udpReject) > 4096 {
		cutoff := now.Add(-30 * time.Second)
		for flow, seen := range rw.udpReject {
			if seen.Before(cutoff) {
				delete(rw.udpReject, flow)
			}
		}
	}
	rw.udpReject[key] = now
	return true
}

func ipv4UDPFlowKey(packet []byte) (string, bool) {
	if !isIPv4UDP(packet) {
		return "", false
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 {
		return "", false
	}
	udp := packet[ihl:]
	return fmt.Sprintf("%08x:%d>%08x:%d", binary.BigEndian.Uint32(packet[12:16]), binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint32(packet[16:20]), binary.BigEndian.Uint16(udp[2:4])), true
}

func isIPv4UDPDstPort(packet []byte, port uint16) bool {
	if !isIPv4UDP(packet) {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 {
		return false
	}
	return binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) == port
}

func MobilePacketFlowDebugStats() string {
	packetFlowTun2Socks.mu.Lock()
	rw := packetFlowTun2Socks.rw
	packetFlowTun2Socks.mu.Unlock()
	if rw == nil {
		return "packetflow=stopped"
	}
	return fmt.Sprintf("packetflow=running in=%d out=%d udp_forwarded=%d dns_seen=%d dns_answered=%d dns_miss=%d dns_a=%d dns_aaaa=%d dns_https=%d dns_svcb=%d dns_other=%d dns_a_ipv4=%d dns_a_empty=%d dns_direct_udp=%d dns_direct_tcp=%d dns_socks=%d dns_cache=%d udp_dropped=%d udp_icmp_rejected=%d", atomic.LoadUint64(&rw.inPackets), atomic.LoadUint64(&rw.outPackets), atomic.LoadUint64(&rw.udpForwarded), atomic.LoadUint64(&rw.dnsSeen), atomic.LoadUint64(&rw.dnsAnswered), atomic.LoadUint64(&rw.dnsMiss), atomic.LoadUint64(&rw.dnsA), atomic.LoadUint64(&rw.dnsAAAA), atomic.LoadUint64(&rw.dnsHTTPS), atomic.LoadUint64(&rw.dnsSVCB), atomic.LoadUint64(&rw.dnsOther), atomic.LoadUint64(&rw.dnsAWithIPv4), atomic.LoadUint64(&rw.dnsAEmpty), atomic.LoadUint64(&rw.dnsDirectUDP), atomic.LoadUint64(&rw.dnsDirectTCP), atomic.LoadUint64(&rw.dnsSocks), atomic.LoadUint64(&rw.dnsCache), atomic.LoadUint64(&rw.udpDropped), atomic.LoadUint64(&rw.udpICMPRejected))
}
