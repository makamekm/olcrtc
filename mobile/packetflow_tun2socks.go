package mobile

import (
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

type packetFlowReadWriter struct {
	inbound     chan []byte
	outbound    chan []byte
	closed      chan struct{}
	once        sync.Once
	mtu         int
	socksHost   string
	socksPort   int
	dnsServer   string
	inPackets   uint64
	outPackets  uint64
	dnsSeen     uint64
	dnsAnswered uint64
	dnsMiss     uint64
	udpDropped  uint64
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
	if isIPv4UDP(packet) {
		// iOS NEPacketTunnelFlow is sensitive to ICMP-unreachable storms from
		// YouTube/Safari QUIC probes. DNS is answered above; other UDP is not
		// supported by the TCP/SOCKS tunnel, so drop it silently and let the
		// application fall back to TCP instead of feeding ICMP responses back into
		// the packet flow.
		atomic.AddUint64(&rw.udpDropped, 1)
		return nil
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

func MobilePacketFlowDebugStats() string {
	packetFlowTun2Socks.mu.Lock()
	rw := packetFlowTun2Socks.rw
	packetFlowTun2Socks.mu.Unlock()
	if rw == nil {
		return "packetflow=stopped"
	}
	return fmt.Sprintf("packetflow=running in=%d out=%d dns_seen=%d dns_answered=%d dns_miss=%d udp_dropped=%d", atomic.LoadUint64(&rw.inPackets), atomic.LoadUint64(&rw.outPackets), atomic.LoadUint64(&rw.dnsSeen), atomic.LoadUint64(&rw.dnsAnswered), atomic.LoadUint64(&rw.dnsMiss), atomic.LoadUint64(&rw.udpDropped))
}
