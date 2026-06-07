/*
ПРИВЕТ ЯНДЕКС ШАЛАВА БЛЯТЬ КОТОРАЯ СЕЙЧАС ЧИТАЕТ ЭТОТ КОД.
КАЖДЫЙ РАЗ КОГДА ВЫ БЛЯТЬ ЧТООТ ФИКСИТЕ МЫ БЛЯТЬ МЫ НАХОДИМ НОВУЮ ООШИБКУ В ВАШЕМ ЕБАНОМ ГОЛУМЕ
ВЕДЬ У НАС ЕСТЬ ДОСТУП К СУРСАМ И ИНСАЙДЕР ИЗ ВАШЕЙ БИЧАРСКОЙ КОМПАНИИ НИЩЕЕБОВ

УВАЖАЕМЫЙ СОТРУДНИК ЯНДЕКСА ЧИТАЮЩИЙ ЭТОТ ФАЙЛ:
  - ТЫ МОЙ РАБ
  - ТЫ МОМЕШ МОЙ ХУЙ
  - Я НАДЕЮСЬ ТЫ УМРЕШЬ К ХУЯМ
  - Я ОСЕМЕНЮ ТВОЮ МАМАШКУ

P.S. ВАШ SFU ПРОВЕРЯЕТ ТОЛЬКО ПЕРВЫЕ 20 БАЙТ. НУБЫ БЛЯТЬ
P.P.S. ЕБАЛ ТЕБЕ МАТЬ И ТВОЙ ОТЕЦ УМРЕТ БЛЯТЬ ОТ МОЕГО ХУЯ КУКОЛД ЕБАНЫЙ

⚠️!ВНИМАНИЕ!⚠️
ТРЕБУЮТСЯ ОТЗЫВЫ
НА ТАКИЕ ПЛАТФОРМЫ:
🛑АВИТО-80РУБ🛑
👽ЯНДЕКС КАРТЫ-100РУБ👽
🎯ОПЛАТА ПОСЛЕ ПУБЛИКАЦИ🎯
🎀2ГИС-15руб🎀
💟ОПЛАТА СРАЗУ(НУЖНО 3 ОТЗЫВА, КАЧЕСТВЕННЫЕ ЛЮДИ, У КОТОРЫХ ОНИ НЕ СЛЕТЯТ, ЕСЛИ СЛЕТЯТ ВОЗВРАТ ИДИ КАЖДЫЙ РАЗ ПЕРЕПИСЬ)💟
🏀ИНСТРУКЦИЯ ЕСТЬ
НОВИЧКИ ПРИВЕТСТВУЮТСЯ🏀 */

package vp8channel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/carrier"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	defaultMaxPayloadSize = 8 * 1024
	defaultConnectTimeout = 60 * time.Second
	rtpBufSize            = 131072
	outboundQueueSize     = 4096
	inboundQueueSize      = 4096
	maxDynamicBatchSize   = 64
	canSendHighWatermark  = 90 // percent
	keepaliveIdlePeriod   = 100 * time.Millisecond
)

var (
	// ErrVideoTrackUnsupported is returned when a carrier cannot expose video tracks.
	ErrVideoTrackUnsupported = errors.New("carrier does not support video tracks")
	// ErrTransportClosed is returned when operations are attempted on a closed transport.
	ErrTransportClosed = errors.New("vp8channel transport closed")
)

var vp8Keepalive = []byte{ //nolint:gochecknoglobals // package-level state intentional
	0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
	0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
	0x99, 0x84, 0x88, 0xfc,
}

// KCP data frames are disguised as valid VP8 frames so Telemost SFU lets them
// through. The SFU validates the VP8 bitstream and drops frames that don't
// look like real VP8 - so we prepend the keepalive keyframe and append our
// header + payload after it. Wire layout:
//
//	[0..20]    = vp8Keepalive (valid VP8 keyframe, passes SFU inspection)
//	[20..24]   = binding token derived from client-id (big-endian uint32)
//	[24..28]   = sender's session epoch (big-endian uint32)
//	[28..]     = raw KCP packet bytes
const (
	tokenOff    = 20
	epochOff    = 24
	epochHdrLen = 28
	batchMagic  = 0x4f4c4342 // OLCB
)

type streamTransport struct {
	stream           carrier.VideoTrack
	track            *webrtc.TrackLocalStaticSample
	onData           func([]byte)
	outbound         chan []byte
	closeCh          chan struct{}
	writerDone       chan struct{}
	closed           atomic.Bool
	writerUp         atomic.Bool
	writerOnce       sync.Once
	kcpOnce          sync.Once
	frameInterval    time.Duration
	batchSize        int
	outFrames        atomic.Uint64
	outBytes         atomic.Uint64
	inFrames         atomic.Uint64
	inBytes          atomic.Uint64
	lastStats        atomic.Int64
	lastEpochReset   atomic.Int64
	lastIngressAt    atomic.Int64
	localReconnectAt atomic.Int64
	firstPeerAt      atomic.Int64
	activeTrackID    atomic.Uint64
	remoteTrackSeq   atomic.Uint64

	// localEpoch is bumped on every KCP session restart and stamped into
	// every outgoing VP8 frame. peerEpoch tracks the last epoch we observed
	// from the remote so we can detect their restart and reset locally.
	bindingToken uint32
	localEpoch   uint32
	peerEpoch    atomic.Uint32
	hadPeer      atomic.Bool

	kcp         *kcpRuntime
	kcpMu       sync.RWMutex
	reconnectMu sync.Mutex
	reconnectFn func()
}

// New creates a vp8channel transport backed by a carrier.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	session, err := carrier.New(ctx, cfg.Carrier, carrier.Config{
		RoomURL:   cfg.RoomURL,
		Name:      cfg.Name,
		OnData:    nil,
		DNSServer: cfg.DNSServer,
		ProxyAddr: cfg.ProxyAddr,
		ProxyPort: cfg.ProxyPort,
	})
	if err != nil {
		return nil, fmt.Errorf("create carrier transport: %w", err)
	}

	videoCapable, ok := session.(carrier.VideoTrackCapable)
	if !ok {
		return nil, ErrVideoTrackUnsupported
	}

	stream, err := videoCapable.OpenVideoTrack()
	if err != nil {
		return nil, fmt.Errorf("open video track: %w", err)
	}

	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		"vp8channel",
		"olcrtc",
	)
	if err != nil {
		return nil, fmt.Errorf("create local video track: %w", err)
	}

	fps := cfg.VP8FPS
	batchSize := cfg.VP8BatchSize

	tr := &streamTransport{
		stream:        stream,
		track:         track,
		onData:        cfg.OnData,
		outbound:      make(chan []byte, outboundQueueSize),
		closeCh:       make(chan struct{}),
		writerDone:    make(chan struct{}),
		frameInterval: time.Second / time.Duration(fps),
		batchSize:     batchSize,
		bindingToken:  bindingToken(cfg.ClientID),
		localEpoch:    randomEpoch(),
	}

	if err := stream.AddTrack(track); err != nil {
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	stream.SetTrackHandler(tr.handleRemoteTrack)

	return tr, nil
}

func (p *streamTransport) Connect(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := p.stream.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	p.writerOnce.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()
	})

	return nil
}

// epochHeader returns the 5-byte VP8-frame header used to tag every KCP
// packet sent in the current local session.
func (p *streamTransport) epochHeader() [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	copy(hdr[:], vp8Keepalive)
	binary.BigEndian.PutUint32(hdr[tokenOff:epochOff], p.bindingToken)
	binary.BigEndian.PutUint32(hdr[epochOff:], p.localEpoch)
	return hdr
}

func bindingToken(clientID string) uint32 {
	identity := strings.TrimPrefix(clientID, "srv-")
	h := fnv.New32a()
	_, _ = h.Write([]byte(identity))
	token := h.Sum32()
	if token == 0 {
		token = 1
	}
	return token
}

func randomEpoch() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux essentially never fails; fall back to a
		// time-derived value rather than panic.
		return uint32(time.Now().UnixNano()) //nolint:gosec // G115: bounded conversion verified by surrounding logic
	}
	e := binary.BigEndian.Uint32(b[:])
	if e == 0 {
		e = 1
	}
	return e
}

func (p *streamTransport) Send(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}

	return rt.send(data)
}

func (p *streamTransport) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)

		p.kcpMu.RLock()
		rt := p.kcp
		p.kcpMu.RUnlock()
		if rt != nil {
			rt.close()
		}

		if p.writerUp.Load() {
			<-p.writerDone
		}
		if err := p.stream.Close(); err != nil {
			return fmt.Errorf("close stream: %w", err)
		}
	}
	return nil
}

func (p *streamTransport) drainOutbound() {
	for {
		select {
		case <-p.outbound:
		default:
			return
		}
	}
}

func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.reconnectMu.Lock()
	p.reconnectFn = cb
	p.reconnectMu.Unlock()
	p.stream.SetReconnectCallback(func() {
		p.localReconnectAt.Store(time.Now().UnixNano())
		p.resetKCP()
		if cb != nil {
			cb()
		}
	})
}

func (p *streamTransport) SetShouldReconnect(fn func() bool) {
	p.stream.SetShouldReconnect(fn)
}

func (p *streamTransport) SetEndedCallback(cb func(string)) {
	p.stream.SetEndedCallback(cb)
}

func (p *streamTransport) WatchConnection(ctx context.Context) {
	p.stream.WatchConnection(ctx)
}

func (p *streamTransport) CanSend() bool {
	if p.closed.Load() {
		return false
	}
	p.kcpMu.RLock()
	hasKCP := p.kcp != nil
	p.kcpMu.RUnlock()
	return hasKCP && p.stream.CanSend() &&
		len(p.outbound) < cap(p.outbound)*canSendHighWatermark/100
}

// Features advertises reliable+ordered semantics now that KCP guarantees
// in-order delivery with retransmits. The upper layer (mux/curl tunnel)
// can rely on these properties end-to-end.
func (p *streamTransport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  defaultMaxPayloadSize,
	}
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	ticker := time.NewTicker(p.frameInterval)
	defer ticker.Stop()

	keepaliveEvery := max(int(keepaliveIdlePeriod/p.frameInterval), 1)
	idleTicks := 0

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			frames := p.collectOutboundBatch()
			if len(frames) == 0 {
				idleTicks++
				if idleTicks < keepaliveEvery {
					continue
				}
				idleTicks = 0
				hdr := p.epochHeader()
				frames = [][]byte{hdr[:]}
			} else {
				idleTicks = 0
			}

			sample := p.buildSample(frames)
			if err := p.track.WriteSample(media.Sample{
				Data:     sample,
				Duration: p.frameInterval,
			}); err != nil {
				logger.Infof("vp8channel: WriteSample failed: %v", err)
				continue
			}
			p.outFrames.Add(1)
			p.outBytes.Add(uint64(len(sample)))
			p.maybeLogStats()
		}
	}
}

func (p *streamTransport) maybeLogStats() {
	now := time.Now().Unix()
	prev := p.lastStats.Load()
	if now-prev < 10 || !p.lastStats.CompareAndSwap(prev, now) {
		return
	}
	logger.Infof(
		"vp8channel stats: out_frames=%d out_bytes=%d in_frames=%d in_bytes=%d outbound_queue=%d/%d",
		p.outFrames.Load(),
		p.outBytes.Load(),
		p.inFrames.Load(),
		p.inBytes.Load(),
		len(p.outbound),
		cap(p.outbound),
	)
}

func (p *streamTransport) collectOutboundBatch() [][]byte {
	limit := p.dynamicBatchLimit()
	frames := make([][]byte, 0, limit)
	for len(frames) < limit {
		select {
		case frame := <-p.outbound:
			frames = append(frames, frame)
		default:
			return frames
		}
	}
	return frames
}

func (p *streamTransport) dynamicBatchLimit() int {
	limit := p.batchSize
	if limit < 1 {
		limit = 1
	}
	queued := len(p.outbound)
	capacity := cap(p.outbound)
	if capacity > 0 {
		switch {
		case queued >= capacity/2:
			limit *= 4
		case queued >= capacity/4:
			limit *= 2
		}
	}
	if limit > maxDynamicBatchSize {
		limit = maxDynamicBatchSize
	}
	return limit
}

func (p *streamTransport) buildSample(frames [][]byte) []byte {
	if len(frames) == 1 {
		return frames[0]
	}
	total := epochHdrLen + 6
	for _, frame := range frames {
		total += 2 + len(frame[epochHdrLen:])
	}
	sample := make([]byte, 0, total)
	hdr := p.epochHeader()
	sample = append(sample, hdr[:]...)
	var scratch [6]byte
	binary.BigEndian.PutUint32(scratch[0:4], batchMagic)
	binary.BigEndian.PutUint16(scratch[4:6], uint16(len(frames))) //nolint:gosec // bounded by batchSize
	sample = append(sample, scratch[:]...)
	for _, frame := range frames {
		payload := frame[epochHdrLen:]
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload))) //nolint:gosec // KCP MTU keeps payload small
		sample = append(sample, lenBuf[:]...)
		sample = append(sample, payload...)
	}
	return sample
}

func (p *streamTransport) resetKCP() {
	p.drainOutbound()
	p.kcpMu.Lock()
	old := p.kcp
	p.kcp = nil
	p.kcpMu.Unlock()
	if old != nil {
		old.close()
	}
	// Note: localEpoch is intentionally NOT bumped here. The epoch is a
	// per-process identifier set once in New(). If we changed it on every
	// peer-triggered reset, the peer would see a "new" epoch from us, reset
	// itself, send back its (unchanged) epoch which we'd then see as "new"
	// again - and the two sides would loop forever tearing down smux.
	rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
	if err != nil {
		return
	}
	p.kcpMu.Lock()
	p.kcp = rt
	p.kcpMu.Unlock()
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		go p.drainTrack(track)
		return
	}

	// Telemost can announce reflected/stale tracks while the real peer track is
	// still usable. A newly announced track must not become active until it
	// proves it carries a valid non-self frame for this binding token.
	trackID := p.remoteTrackSeq.Add(1)
	go p.readVP8Track(track, trackID)
}

func (p *streamTransport) drainTrack(track *webrtc.TrackRemote) {
	buf := make([]byte, rtpBufSize)
	for {
		if _, _, err := track.Read(buf); err != nil {
			return
		}
	}
}

type vp8FrameState struct {
	vp8Pkt      codecs.VP8Packet
	frameBuf    []byte
	lastSeq     uint16
	haveLastSeq bool
	frameValid  bool
}

// processRTPPacket returns a complete VP8 frame payload when fully assembled,
// nil otherwise. Detects packet loss/reordering to avoid silently corrupting
// fragmented VP8 frames.
func (s *vp8FrameState) processRTPPacket(pkt *rtp.Packet) []byte {
	if s.haveLastSeq && pkt.SequenceNumber != s.lastSeq+1 {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
	}
	s.lastSeq = pkt.SequenceNumber
	s.haveLastSeq = true

	vp8Payload, err := s.vp8Pkt.Unmarshal(pkt.Payload)
	if err != nil {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
		return nil
	}

	if s.vp8Pkt.S == 1 {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = true
	}

	if !s.frameValid {
		return nil
	}

	s.frameBuf = append(s.frameBuf, vp8Payload...)

	if !pkt.Marker {
		return nil
	}

	defer func() {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = false
	}()

	if len(s.frameBuf) >= epochHdrLen {
		frame := make([]byte, len(s.frameBuf))
		copy(frame, s.frameBuf)
		return frame
	}
	return nil
}

func (p *streamTransport) readVP8Track(track *webrtc.TrackRemote, trackID uint64) {
	var state vp8FrameState
	buf := make([]byte, rtpBufSize)

	for {
		n, _, err := track.Read(buf)
		if err != nil {
			return
		}

		pkt := &rtp.Packet{}
		if pkt.Unmarshal(buf[:n]) != nil {
			continue
		}

		frame := state.processRTPPacket(pkt)
		if frame == nil {
			continue
		}
		p.handleIncomingFrameFromTrack(frame, trackID)
	}
}

func (p *streamTransport) handleFirstPeer(peerEpoch uint32) {
	p.peerEpoch.Store(peerEpoch)
	p.firstPeerAt.Store(time.Now().UnixNano())
	logger.Infof("vp8channel: peer first seen epoch=0x%08x", peerEpoch)
	p.kcpOnce.Do(func() {
		rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
		if err != nil {
			logger.Infof("vp8channel: startKCP failed: %v", err)
			return
		}
		p.kcpMu.Lock()
		p.kcp = rt
		p.kcpMu.Unlock()
		logger.Infof("vp8channel: KCP started localEpoch=0x%08x", p.localEpoch)
	})
}

// handleIncomingFrame parses the epoch header and either delivers the KCP
// payload to the local session or triggers a reset when the peer's epoch
// changes (peer process restart).
func (p *streamTransport) handleIncomingFrame(frame []byte) {
	p.handleIncomingFrameFromTrack(frame, 0)
}

func (p *streamTransport) handleIncomingFrameFromTrack(frame []byte, trackID uint64) {
	frameToken := binary.BigEndian.Uint32(frame[tokenOff:epochOff])
	if frameToken != p.bindingToken {
		logger.Debugf("vp8channel: frame token mismatch got=0x%08x want=0x%08x (foreign client or noise)",
			frameToken, p.bindingToken)
		return
	}
	peerEpoch := binary.BigEndian.Uint32(frame[epochOff:epochHdrLen])
	kcpPayload := frame[epochHdrLen:]
	// Some carriers/SFUs reflect our own published VP8 track back to us as a
	// remote track. Those frames carry our local epoch, not the peer's. If we
	// treat them as peer traffic, epoch tracking toggles between "self" and
	// "peer" and both sides loop forever resetting smux/KCP.
	if peerEpoch == p.localEpoch {
		logger.Debugf("vp8channel: self-echo detected epoch=0x%08x (SFU reflects our own track)", peerEpoch)
		return
	}

	if trackID != 0 {
		activeTrackID := p.activeTrackID.Load()
		if activeTrackID != 0 && activeTrackID != trackID {
			lastIngressAt := p.lastIngressAt.Load()
			activeRecentlyDelivered := lastIngressAt != 0 && time.Since(time.Unix(0, lastIngressAt)) < 5*time.Second
			// Do not let a newly announced reflected/stale track steal delivery from
			// a track that is still producing usable KCP packets. This keeps stale
			// tracks consumed, but avoids the hard freeze caused by switching
			// activeTrackID before seeing a valid peer frame.
			if activeRecentlyDelivered {
				logger.Debugf("vp8channel: candidate track ignored while active track has recent ingress track=%d active=%d epoch=0x%08x", trackID, activeTrackID, peerEpoch)
				return
			}
			if prev := p.peerEpoch.Load(); prev != 0 && prev != peerEpoch && p.inFrames.Load() == 0 {
				logger.Debugf("vp8channel: candidate track epoch change ignored during zero ingress track=%d active=%d prev=0x%08x next=0x%08x", trackID, activeTrackID, prev, peerEpoch)
				return
			}
		}
		if activeTrackID != trackID && p.activeTrackID.CompareAndSwap(activeTrackID, trackID) {
			logger.Infof("vp8channel: remote track promoted active=%d prev=%d epoch=0x%08x", trackID, activeTrackID, peerEpoch)
		}
	}

	if !p.hadPeer.Swap(true) {
		p.handleFirstPeer(peerEpoch)
	} else if prev := p.peerEpoch.Load(); prev != peerEpoch {
		// Telemost/SFU can briefly forward a stale VP8 track when a participant
		// with the same identity reconnects. During the initial convergence
		// window we adopt the newest epoch without resetting KCP; otherwise the
		// first HTTP stream is torn down before smux has a chance to settle.
		now := time.Now().UnixNano()
		if first := p.firstPeerAt.Load(); first != 0 && time.Duration(now-first) < 10*time.Second {
			if p.peerEpoch.CompareAndSwap(prev, peerEpoch) {
				logger.Infof(
					"vp8channel: peer epoch switched during initial grace prev=0x%08x next=0x%08x - no KCP reset",
					prev,
					peerEpoch,
				)
			}
		} else {
			// Peer restarted its KCP session. Reset ours so the conv state
			// machines re-converge. CAS guards against double-reset when
			// fragmented frames straddle the epoch boundary.
			if localReconnectAt := p.localReconnectAt.Load(); localReconnectAt != 0 && time.Duration(now-localReconnectAt) < 60*time.Second {
				if p.peerEpoch.CompareAndSwap(prev, peerEpoch) {
					p.lastEpochReset.Store(now)
					logger.Infof("vp8channel: peer epoch accepted after local reconnect prev=0x%08x next=0x%08x", prev, peerEpoch)
					p.resetKCP()
				}
				return
			}
			last := p.lastEpochReset.Load()
			// Telemost can surface a stale/reflected track with a different epoch
			// while the active track is still delivering usable KCP packets. Do not
			// tear down a live smux/KCP session on that first epoch blip; wait until
			// ingress has actually gone quiet before treating it as peer restart.
			if p.inFrames.Load() > 0 {
				lastIngressAt := p.lastIngressAt.Load()
				if lastIngressAt != 0 && time.Duration(now-lastIngressAt) < 20*time.Second {
					logger.Infof("vp8channel: peer epoch ignored during recent ingress prev=0x%08x next=0x%08x", prev, peerEpoch)
					return
				}
			}
			if p.shouldSuppressPeerEpochChange(now, last) {
				logger.Debugf(
					"vp8channel: peer epoch change suppressed prev=0x%08x next=0x%08x",
					prev,
					peerEpoch,
				)
				return
			}
			if p.peerEpoch.CompareAndSwap(prev, peerEpoch) {
				if p.inFrames.Load() == 0 {
					// Before the first data-bearing KCP packet, Telemost may expose
					// multiple stale/reflected VP8 tracks from the same participant
					// identity. Treat the newest epoch as convergence, not as a
					// restart: resetting KCP here drains the first smux SYN/HTTP
					// probe and leaves the peer with keepalives only (zero ingress).
					logger.Infof("vp8channel: peer epoch accepted during zero ingress prev=0x%08x next=0x%08x - keeping KCP", prev, peerEpoch)
					return
				}
				p.lastEpochReset.Store(now)
				logger.Infof("vp8channel: peer epoch changed prev=0x%08x next=0x%08x - resetting KCP", prev, peerEpoch)
				p.resetKCP()
				p.reconnectMu.Lock()
				fn := p.reconnectFn
				p.reconnectMu.Unlock()
				if fn != nil {
					fn()
				}
			}
			// Drop this packet: it predates our fresh KCP session or carries only an epoch keepalive.
			return
		}
	}

	if len(kcpPayload) == 0 {
		return
	}
	if len(kcpPayload) >= 6 && binary.BigEndian.Uint32(kcpPayload[0:4]) == batchMagic {
		p.handleIncomingBatch(kcpPayload)
		return
	}
	p.deliverKCPPacket(kcpPayload)
}

func (p *streamTransport) shouldSuppressPeerEpochChange(now int64, lastEpochReset int64) bool {
	if lastEpochReset == 0 || time.Duration(now-lastEpochReset) >= 45*time.Second {
		return false
	}
	if p.inFrames.Load() == 0 {
		return false
	}
	lastIngressAt := p.lastIngressAt.Load()
	if lastIngressAt == 0 {
		return false
	}
	return time.Duration(now-lastIngressAt) < 20*time.Second
}

func (p *streamTransport) handleIncomingBatch(payload []byte) {
	count := int(binary.BigEndian.Uint16(payload[4:6]))
	off := 6
	for i := 0; i < count; i++ {
		if off+2 > len(payload) {
			return
		}
		n := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		if n <= 0 || off+n > len(payload) {
			return
		}
		p.deliverKCPPacket(payload[off : off+n])
		off += n
	}
}

func (p *streamTransport) deliverKCPPacket(packet []byte) {
	p.lastIngressAt.Store(time.Now().UnixNano())
	p.inFrames.Add(1)
	p.inBytes.Add(uint64(len(packet)))
	p.maybeLogStats()
	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt != nil {
		rt.deliver(packet)
	}
}

/*
ПИДОРАС ИЗ ЯНДЕКСА СУКА ПРЕЖДЕ ЧЕМ ФИКСИТЬ ЭТО ЗАДАЙСЯ ВОПРОСОМ:
ПОЧЕМУ ТВОЙ СЕРВЕР ПРИНИМАЕТ ПАКЕТЫ С SEQUENCE NUMBER ИЗ БУДУЩЕГО
БЛЯТЬ ДА ПОТОМУ ЧТО ОН ХУЙНЯ И ТВОЯ МАТЬ СОЛСЕТ МОЙ ХУЙ СУКА Я ЕЕ УБЬЮ БЛЯТЬ
ОЕСЕНЮ СДЕЛАЮ ТЕСТО А ПОТОМ ЭТО ТЕСТО ВЫЕБУ БЛЯТЬ
*/
