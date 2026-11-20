// Package directpath carries the tunnel's KCP packets over a direct WebRTC
// data channel between client and server, bypassing the conference SFU and
// its packet-rate limits. Negotiation runs over the existing tunnel, so no
// extra signalling server or TURN relay is involved. When the direct path is
// down the transport keeps using the conference path; switching either way
// does not reset the KCP/smux session.
package directpath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/pion/webrtc/v4"
)

const (
	msgFrame byte = 0
	msgPing  byte = 1

	pingInterval     = time.Second
	unhealthyAfter   = 4 * time.Second
	gatherTimeout    = 4 * time.Second
	connectTimeout   = 12 * time.Second
	maxBufferedBytes = 4 << 20

	// EnvPort enables the server side and fixes its UDP port.
	EnvPort = "OLCRTC_DIRECT_PORT"
	// EnvPublicIP overrides the advertised public address.
	EnvPublicIP = "OLCRTC_DIRECT_PUBLIC_IP"
	// EnvNATPMP asks the LAN gateway to forward EnvPort ("0" disables).
	EnvNATPMP = "OLCRTC_DIRECT_NATPMP"
	// EnvDisable turns the client side off ("1").
	EnvDisable = "OLCRTC_DIRECT_DISABLE"
)

// ErrUnsupported means the peer does not offer a direct path.
var ErrUnsupported = errors.New("direct path not supported by server")

// clientSTUN gives mobile clients a server-reflexive candidate even when the
// OS hides interface lists (Android 11+). Yandex STUN answers from networks
// where foreign STUN servers are blocked.
var clientSTUN = []webrtc.ICEServer{{URLs: []string{"stun:stun.rtc.yandex.net:3478"}}} //nolint:gochecknoglobals // static config

// Attacher is implemented by transports that can route over a Path.
type Attacher interface {
	AttachDirectPath(p *Path)
}

// LinkAttacher is implemented by links that forward a Path to their transport.
type LinkAttacher interface {
	AttachDirectPath(p *Path) bool
}

// Path is one established direct data channel.
type Path struct {
	pc                     *webrtc.PeerConnection
	dc                     *webrtc.DataChannel
	open                   atomic.Bool
	lastRecv               atomic.Int64
	onFrame                atomic.Pointer[func([]byte)]
	done                   chan struct{}
	closeOnce              sync.Once
	sentFrames, recvFrames atomic.Uint64
}

func newPath(pc *webrtc.PeerConnection) *Path {
	return &Path{pc: pc, done: make(chan struct{})}
}

func (p *Path) bind(dc *webrtc.DataChannel, ready chan<- struct{}) {
	p.dc = dc
	dc.OnOpen(func() {
		p.open.Store(true)
		p.lastRecv.Store(time.Now().UnixNano())
		go p.pingLoop()
		select {
		case ready <- struct{}{}:
		default:
		}
	})
	dc.OnClose(func() { p.Close() })
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if len(msg.Data) == 0 {
			return
		}
		p.lastRecv.Store(time.Now().UnixNano())
		if msg.Data[0] != msgFrame {
			return
		}
		p.recvFrames.Add(1)
		if fn := p.onFrame.Load(); fn != nil {
			(*fn)(msg.Data[1:])
		}
	})
}

// OnFrame sets the receiver for tunnel frames arriving over this path.
func (p *Path) OnFrame(fn func([]byte)) { p.onFrame.Store(&fn) }

// Healthy reports whether frames should be routed over this path.
func (p *Path) Healthy() bool {
	if p == nil || !p.open.Load() {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
	}
	return time.Since(time.Unix(0, p.lastRecv.Load())) < unhealthyAfter
}

// Send queues one tunnel frame; false means the caller must use another path.
func (p *Path) Send(frame []byte) bool {
	if !p.Healthy() || p.dc.BufferedAmount() > maxBufferedBytes {
		return false
	}
	msg := make([]byte, 1+len(frame))
	msg[0] = msgFrame
	copy(msg[1:], frame)
	if err := p.dc.Send(msg); err != nil {
		return false
	}
	p.sentFrames.Add(1)
	return true
}

// Done is closed when the path is gone for good.
func (p *Path) Done() <-chan struct{} { return p.done }

// Stats returns frames sent and received over the path.
func (p *Path) Stats() (sent, received uint64) { return p.sentFrames.Load(), p.recvFrames.Load() }

// Close tears the path down.
func (p *Path) Close() {
	p.closeOnce.Do(func() {
		p.open.Store(false)
		close(p.done)
		_ = p.pc.Close()
	})
}

func (p *Path) pingLoop() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-t.C:
			if p.dc.ReadyState() == webrtc.DataChannelStateOpen {
				_ = p.dc.Send([]byte{msgPing})
			}
			if p.open.Load() && time.Since(time.Unix(0, p.lastRecv.Load())) > 3*unhealthyAfter {
				logger.Infof("directpath: no traffic for %v, closing", 3*unhealthyAfter)
				p.Close()
				return
			}
		}
	}
}

func watchState(pc *webrtc.PeerConnection, path *Path) {
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logger.Infof("directpath: peer connection %s", state)
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			path.Close()
		}
	})
}

func gatherComplete(ctx context.Context, pc *webrtc.PeerConnection) {
	done := webrtc.GatheringCompletePromise(pc)
	select {
	case <-done:
	case <-time.After(gatherTimeout):
	case <-ctx.Done():
	}
}

func unordered() *webrtc.DataChannelInit {
	ordered := false
	retransmits := uint16(0)
	return &webrtc.DataChannelInit{Ordered: &ordered, MaxRetransmits: &retransmits}
}

// ClientEnabled reports whether the client should try a direct path.
func ClientEnabled() bool {
	v := strings.TrimSpace(os.Getenv(EnvDisable))
	return v != "1" && !strings.EqualFold(v, "true")
}

// Offerer is the client half: Offer builds the SDP to send, Finish applies
// the server answer and waits until the data channel opens.
type Offerer struct {
	pc    *webrtc.PeerConnection
	path  *Path
	ready chan struct{}
}

// NewOfferer creates the client peer connection and its local offer.
func NewOfferer(ctx context.Context) (*Offerer, string, error) {
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: clientSTUN})
	if err != nil {
		return nil, "", fmt.Errorf("new peer connection: %w", err)
	}
	o := &Offerer{pc: pc, path: newPath(pc), ready: make(chan struct{}, 1)}
	watchState(pc, o.path)
	dc, err := pc.CreateDataChannel("olcrtc", unordered())
	if err != nil {
		_ = pc.Close()
		return nil, "", fmt.Errorf("create data channel: %w", err)
	}
	o.path.bind(dc, o.ready)
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		_ = pc.Close()
		return nil, "", fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		_ = pc.Close()
		return nil, "", fmt.Errorf("set local offer: %w", err)
	}
	gatherComplete(ctx, pc)
	return o, pc.LocalDescription().SDP, nil
}

// Finish applies the answer and returns the open path.
func (o *Offerer) Finish(ctx context.Context, answerSDP string) (*Path, error) {
	if err := o.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answerSDP}); err != nil {
		o.path.Close()
		return nil, fmt.Errorf("set remote answer: %w", err)
	}
	select {
	case <-o.ready:
		return o.path, nil
	case <-o.path.Done():
		return nil, errors.New("direct path closed before opening")
	case <-time.After(connectTimeout):
		o.path.Close()
		return nil, errors.New("direct path did not connect")
	case <-ctx.Done():
		o.path.Close()
		return nil, ctx.Err()
	}
}

// Abort releases an offer that will not be completed.
func (o *Offerer) Abort() { o.path.Close() }

// Server owns the shared UDP port all direct peer connections use.
type Server struct {
	api      *webrtc.API
	publicIP string
	port     int
	natpmp   *natpmpMapping
}

// ServerFromEnv starts the server side when OLCRTC_DIRECT_PORT is set;
// it returns nil, nil when direct paths are disabled.
func ServerFromEnv(ctx context.Context) (*Server, error) {
	port, err := strconv.Atoi(strings.TrimSpace(os.Getenv(EnvPort)))
	if err != nil || port <= 0 || port > 65535 {
		return nil, nil //nolint:nilnil // disabled is not an error
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen udp %d: %w", port, err)
	}
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: port})
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listen tcp %d: %w", port, err)
	}
	s := &Server{port: port, publicIP: strings.TrimSpace(os.Getenv(EnvPublicIP))}
	if v := strings.TrimSpace(os.Getenv(EnvNATPMP)); v != "0" && !strings.EqualFold(v, "false") {
		if m, err := mapPortNATPMP(ctx, port); err != nil {
			logger.Infof("directpath: NAT-PMP mapping unavailable: %v", err)
		} else {
			s.natpmp = m
			if s.publicIP == "" {
				s.publicIP = m.externalIP
			}
		}
	}
	engine := webrtc.SettingEngine{}
	engine.SetICEUDPMux(webrtc.NewICEUDPMux(nil, udp))
	engine.SetICETCPMux(webrtc.NewICETCPMux(nil, tcp, 64))
	engine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeTCP4})
	if s.publicIP != "" {
		// Keep LAN host candidates and add the public address on top.
		engine.SetNAT1To1IPs([]string{s.publicIP}, webrtc.ICECandidateTypeSrflx)
	}
	s.api = webrtc.NewAPI(webrtc.WithSettingEngine(engine))
	go func() {
		<-ctx.Done()
		_ = udp.Close()
		_ = tcp.Close()
	}()
	logger.Infof("directpath: server listening on udp/tcp %d public=%s", port, nonEmpty(s.publicIP, "unknown"))
	return s, nil
}

// Answer accepts a client offer and returns the answer plus a path that
// becomes usable once the client connects.
func (s *Server) Answer(ctx context.Context, offerSDP string) (*Path, string, error) {
	pc, err := s.api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, "", fmt.Errorf("new peer connection: %w", err)
	}
	path := newPath(pc)
	watchState(pc, path)
	ready := make(chan struct{}, 1)
	pc.OnDataChannel(func(dc *webrtc.DataChannel) { path.bind(dc, ready) })
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offerSDP}); err != nil {
		path.Close()
		return nil, "", fmt.Errorf("set remote offer: %w", err)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		path.Close()
		return nil, "", fmt.Errorf("create answer: %w", err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		path.Close()
		return nil, "", fmt.Errorf("set local answer: %w", err)
	}
	gatherComplete(ctx, pc)
	go func() {
		select {
		case <-ready:
		case <-path.Done():
		case <-time.After(connectTimeout + gatherTimeout):
			path.Close()
		}
	}()
	return path, pc.LocalDescription().SDP, nil
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
