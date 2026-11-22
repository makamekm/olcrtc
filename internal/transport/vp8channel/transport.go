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
	"github.com/openlibrecommunity/olcrtc/internal/directpath"
	kcp "github.com/xtaci/kcp-go/v5"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/carrier"
	"github.com/openlibrecommunity/olcrtc/internal/clientidentity"
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
	// After deepIdleAfter without payload the keepalive slows to
	// keepaliveDeepIdlePeriod (override OLCRTC_VP8_IDLE_KEEPALIVE_MS): ten
	// frames a second in both directions kept phone radios (LTE in
	// particular) from ever dropping to their low-power state.
	keepaliveDeepIdlePeriod = time.Second
	deepIdleAfter           = 5 * time.Second
	// minFramesBetweenKeyframes keeps a slow idle stream from turning into
	// keyframe-only video, which is what made Telemost throttle rooms.
	minFramesBetweenKeyframes = 4
	peerIngressIdlePeriod     = 3 * time.Second

	// defaultMaxSampleBytes caps one VP8 sample so it fits into a single RTP
	// packet (pion packetizes at a 1200-byte MTU). Telemost drops video above
	// roughly 1 Mbit/s per subscriber; a multi-packet sample loses every byte
	// when any one of its packets is dropped, so large batches collapse KCP.
	defaultMaxSampleBytes = 1100
	// minSamplesPerSecond is the pacing floor for one-packet samples
	// (override: OLCRTC_VP8_MIN_SPS). With keyframe-only video Telemost
	// throttled anything above ~600/s; with one keyframe per second the
	// measured download/upload is ~230/160 KB/s at 600/s, ~470/260 at 1200/s,
	// ~500/450 at 1600/s and only marginally more above that.
	minSamplesPerSecond = 1600
	maxSampleBytesEnv   = "OLCRTC_VP8_MAX_SAMPLE_BYTES"
	keyframeIntervalEnv = "OLCRTC_VP8_KEYFRAME_INTERVAL_MS"
	// Telemost throttles a room to ~3 forwarded frames/s once it has carried a
	// stream in which every frame is a keyframe; real cameras send one about
	// every second, so do the same.
	defaultKeyframeInterval = time.Second
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

	// The server stamps the client session (epoch) it currently serves into
	// the VP8 partition bytes of the prefix, which receivers otherwise ignore:
	//	[12..16] = served client epoch, [16..18] = servedMarker
	// After a client restart (e.g. a Wi-Fi/LTE switch) the server keeps
	// sending its old KCP session's (re)transmissions for a few seconds until
	// it adopts the new client epoch. Without this stamp the new client fed
	// them into its fresh KCP and their stale ACKs wedged the new session.
	servedEpochOff = 12
	servedMarkOff  = 16
	servedMarker   = 0x4f53 // OS
)

type streamTransport struct {
	stream              carrier.VideoTrack
	track               *webrtc.TrackLocalStaticSample
	onData              func([]byte)
	outbound            chan []byte
	closeCh             chan struct{}
	writerDone          chan struct{}
	closed              atomic.Bool
	writerUp            atomic.Bool
	writerOnce          sync.Once
	kcpOnce             sync.Once
	frameInterval       time.Duration
	batchSize           int
	maxSampleBytes      int
	keyframeInterval    time.Duration
	lastKeyframeAt      time.Time
	framesSinceKeyframe int
	pendingMu           sync.Mutex
	pending             []byte
	outFrames           atomic.Uint64
	outBytes            atomic.Uint64
	directOutBytes      atomic.Uint64 // bytes sent over the direct path (drives directCC)
	ccWnd               ccWindow      // directCC send window, 0 when inactive
	inFrames            atomic.Uint64
	inBytes             atomic.Uint64
	idleNonce           atomic.Uint64
	lastStats           atomic.Int64
	lastEpochReset      atomic.Int64
	lastIngressAt       atomic.Int64
	localReconnectAt    atomic.Int64
	firstPeerAt         atomic.Int64

	// localEpoch is bumped on every KCP session restart and stamped into
	// every outgoing VP8 frame. peerEpoch tracks the last epoch we observed
	// from the remote so we can detect their restart and reset locally.
	bindingToken       uint32
	peerBindingToken   uint32
	legacyBindingToken uint32
	publishLegacy      bool
	serverRole         bool
	localEpoch         atomic.Uint32
	// direct is the optional peer-to-peer data channel; KCP packets prefer it
	// while it is healthy and fall back to the conference path otherwise.
	direct atomic.Pointer[directpath.Path]
	// ownEpochs remembers every epoch this process has published so SFU
	// reflections of an earlier local session still count as self-echo.
	ownEpochs sync.Map
	// One device per key: servedSelfAt is the last server frame stamped
	// with our current epoch, foreignSince the first frame since then that
	// was stamped for a session that is not ours. If the server keeps
	// serving someone else for keyInUseAfter, busyFn reports it once.
	servedSelfAt        atomic.Int64
	foreignSince        atomic.Int64
	busyFired           atomic.Bool
	busyMu              sync.Mutex
	busyFn              func()
	peerEpoch           atomic.Uint32
	peerWireToken       atomic.Uint32
	directionalPeerSeen atomic.Bool
	hadPeer             atomic.Bool
	// retiredPeerEpochs prevents delayed SFU frames from rolling selection back
	// to an epoch that has already been replaced by a newer peer process.
	retiredPeerEpochs sync.Map
	// initialPeerPromoted locks the first epoch change seen during SFU
	// convergence. Telemost can keep sending the stale track after exposing the
	// current one; feeding both epochs into one KCP runtime corrupts its state.
	initialPeerPromoted atomic.Bool

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

	outboundToken, peerToken := directionalBindingTokens(cfg.ClientID)
	serverRole := strings.HasPrefix(cfg.ClientID, "srv-")
	tr := &streamTransport{
		stream:             stream,
		track:              track,
		onData:             cfg.OnData,
		outbound:           make(chan []byte, outboundQueueSize),
		closeCh:            make(chan struct{}),
		writerDone:         make(chan struct{}),
		frameInterval:      sampleInterval(fps),
		batchSize:          batchSize,
		maxSampleBytes:     maxSampleBytesFromEnv(),
		keyframeInterval:   keyframeIntervalFromEnv(),
		bindingToken:       outboundToken,
		peerBindingToken:   peerToken,
		legacyBindingToken: bindingToken(cfg.ClientID),
		publishLegacy:      serverRole,
		serverRole:         serverRole,
	}

	if err := stream.AddTrack(track); err != nil {
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	tr.setLocalEpoch(randomEpoch())
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
	return p.epochHeaderForToken(p.bindingToken)
}

func (p *streamTransport) epochHeaderForToken(token uint32) [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	copy(hdr[:], vp8Keepalive)
	binary.BigEndian.PutUint32(hdr[tokenOff:epochOff], token)
	binary.BigEndian.PutUint32(hdr[epochOff:], p.localEpoch.Load())
	return hdr
}

func bindingToken(clientID string) uint32 {
	identity := clientidentity.Normalize(clientID)
	h := fnv.New32a()
	_, _ = h.Write([]byte(identity))
	token := h.Sum32()
	if token == 0 {
		token = 1
	}
	return token
}

func directionalBindingTokens(clientID string) (outbound uint32, peer uint32) {
	identity := clientidentity.Normalize(clientID)
	if strings.HasPrefix(clientID, "srv-") {
		return bindingToken(identity + "\x00srv"), bindingToken(identity + "\x00cnc")
	}
	return bindingToken(identity + "\x00cnc"), bindingToken(identity + "\x00srv")
}

func (p *streamTransport) expectedPeerBindingToken() uint32 {
	if p.peerBindingToken != 0 {
		return p.peerBindingToken
	}
	// Tests and legacy in-package constructors use one symmetric token.
	return p.bindingToken
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

// sampleInterval converts the configured vp8-fps into the minimum spacing
// between samples. Samples are single-RTP-packet sized, so the rate is the
// tunnel's packet budget: Telemost forwards a few hundred such packets per
// second, while the 25-60 fps values baked into existing connection tokens
// would cap the tunnel at ~60 KB/s. Those values are treated as a floor.
func sampleInterval(fps int) time.Duration {
	return time.Second / time.Duration(max(fps, envInt("OLCRTC_VP8_MIN_SPS", minSamplesPerSecond)))
}

func maxSampleBytesFromEnv() int {
	raw := strings.TrimSpace(os.Getenv(maxSampleBytesEnv))
	if raw == "" {
		return defaultMaxSampleBytes
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return defaultMaxSampleBytes
	}
	return value
}

// keyframeIntervalFromEnv returns how often a sample is marked as a VP8
// keyframe; 0 (OLCRTC_VP8_KEYFRAME_INTERVAL_MS=0) marks every sample.
// envInt reads a positive integer tuning override, falling back to def.
func envInt(name string, def int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value <= 0 {
		return def
	}
	return value
}

func keyframeIntervalFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(keyframeIntervalEnv))
	if raw == "" {
		return defaultKeyframeInterval
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return defaultKeyframeInterval
	}
	return time.Duration(value) * time.Millisecond
}

// markFrameType flips the VP8 frame-type bit so that only one sample per
// keyframeInterval claims to be a keyframe, like a real camera stream. The
// receiver ignores the 20-byte VP8 prefix, so this is wire compatible.
func (p *streamTransport) markFrameType(sample []byte, now time.Time) {
	if p.keyframeInterval <= 0 || len(sample) == 0 {
		return
	}
	elapsed := now.Sub(p.lastKeyframeAt)
	due := elapsed >= p.keyframeInterval && p.framesSinceKeyframe >= minFramesBetweenKeyframes
	if p.lastKeyframeAt.IsZero() || due || elapsed >= 5*p.keyframeInterval {
		p.lastKeyframeAt = now
		p.framesSinceKeyframe = 0
		sample[0] &^= 0x01
		return
	}
	p.framesSinceKeyframe++
	sample[0] |= 0x01
}

// stampServedEpoch marks which client session a server sample belongs to.
func (p *streamTransport) stampServedEpoch(sample []byte) {
	if !p.serverRole || len(sample) < epochHdrLen {
		return
	}
	binary.BigEndian.PutUint32(sample[servedEpochOff:servedMarkOff], p.peerEpoch.Load())
	binary.BigEndian.PutUint16(sample[servedMarkOff:servedMarkOff+2], servedMarker)
}

// keyInUseAfter is how long the server may keep serving another device's
// session before this client gives up. A restart of the same device is
// taken over after the old session idles for 3 s, well inside this window.
const keyInUseAfter = 12 * time.Second

// servedOtherSession reports whether a frame from a server that stamps its
// served session was meant for another session: an earlier one of this
// client, or another device using the same key (tracked for busyFn).
func (p *streamTransport) servedOtherSession(frame []byte) bool {
	if p.serverRole || len(frame) < epochHdrLen ||
		binary.BigEndian.Uint16(frame[servedMarkOff:servedMarkOff+2]) != servedMarker {
		return false
	}
	served := binary.BigEndian.Uint32(frame[servedEpochOff:servedMarkOff])
	now := time.Now().UnixNano()
	if served == p.localEpoch.Load() {
		p.servedSelfAt.Store(now)
		p.foreignSince.Store(0)
		return false
	}
	if served != 0 && !p.isOwnEpoch(served) {
		p.noteForeignServed(now)
	}
	return true
}

func (p *streamTransport) noteForeignServed(now int64) {
	since := p.foreignSince.Load()
	if since == 0 {
		p.foreignSince.CompareAndSwap(0, now)
		return
	}
	if time.Duration(now-since) < keyInUseAfter || p.servedSelfAt.Load() > since {
		return
	}
	if !p.busyFired.CompareAndSwap(false, true) {
		return
	}
	logger.Infof("vp8channel: server has served another device with this key for %s - giving up", keyInUseAfter)
	p.busyMu.Lock()
	fn := p.busyFn
	p.busyMu.Unlock()
	if fn != nil {
		go fn()
	}
}

// SetBusyCallback registers the one device per key callback.
func (p *streamTransport) SetBusyCallback(cb func()) {
	p.busyMu.Lock()
	p.busyFn = cb
	p.busyMu.Unlock()
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
	p.pendingMu.Lock()
	p.pending = nil
	p.pendingMu.Unlock()
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
		p.startNewLocalSession()
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

	keepalive := time.NewTimer(keepaliveIdlePeriod)
	defer keepalive.Stop()
	var lastWrite time.Time
	lastPayloadAt := time.Now()
	deepIdlePeriod := time.Duration(envInt("OLCRTC_VP8_IDLE_KEEPALIVE_MS", int(keepaliveDeepIdlePeriod/time.Millisecond))) * time.Millisecond

	for {
		var frames [][]byte
		idle := false
		if p.hasQueuedOutbound() {
			frames = p.pacedOutboundBatch(lastWrite)
		} else {
			select {
			case <-p.closeCh:
				return
			case frame := <-p.outbound:
				p.deferOutbound(frame)
				frames = p.pacedOutboundBatch(lastWrite)
			case <-keepalive.C:
				frames = [][]byte{p.buildIdleFrame()}
				idle = true
			}
		}
		if p.closed.Load() {
			return
		}
		if len(frames) == 0 {
			// drainOutbound raced with us after a KCP reset.
			continue
		}

		lastWrite = p.writeFrames(frames, lastWrite)
		if !idle {
			lastPayloadAt = lastWrite
		}
		if lastWrite.Sub(lastPayloadAt) >= deepIdleAfter {
			keepalive.Reset(deepIdlePeriod)
		} else {
			keepalive.Reset(keepaliveIdlePeriod)
		}
	}
}

func (p *streamTransport) hasQueuedOutbound() bool {
	p.pendingMu.Lock()
	pending := p.pending != nil
	p.pendingMu.Unlock()
	return pending || len(p.outbound) > 0
}

// deferOutbound parks a frame taken off the queue so collectOutboundBatch
// sends it first. Only the writer calls it, and only when nothing is parked.
func (p *streamTransport) deferOutbound(frame []byte) {
	p.pendingMu.Lock()
	p.pending = frame
	p.pendingMu.Unlock()
}

// pacedOutboundBatch waits until frameInterval has passed since the previous
// sample, then collects whatever accumulated in the meantime.
func (p *streamTransport) pacedOutboundBatch(lastWrite time.Time) [][]byte {
	if wait := p.frameInterval - time.Since(lastWrite); wait > 0 && !lastWrite.IsZero() {
		timer := time.NewTimer(wait)
		select {
		case <-p.closeCh:
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return p.collectOutboundBatch()
}

func (p *streamTransport) writeFrames(frames [][]byte, lastWrite time.Time) time.Time {
	sample := p.buildSample(frames)
	// RTP timestamps must follow wall-clock time: samples are sent on demand,
	// so a fixed per-sample duration would drift away from real time.
	now := time.Now()
	duration := p.frameInterval
	if !lastWrite.IsZero() {
		duration = max(now.Sub(lastWrite), time.Millisecond)
	}
	p.markFrameType(sample, now)
	p.stampServedEpoch(sample)
	if err := p.track.WriteSample(media.Sample{
		Data:     sample,
		Duration: duration,
	}); err != nil {
		logger.Infof("vp8channel: WriteSample failed: %v", err)
		return now
	}
	p.outFrames.Add(1)
	p.outBytes.Add(uint64(len(sample)))
	// Legacy (pre-directional) clients need a copy stamped with the symmetric
	// token. Once a directional peer is seen, legacy ingress is rejected for
	// the rest of this process, so the copy would only double egress.
	if p.publishLegacy && !p.directionalPeerSeen.Load() {
		legacySample := append([]byte(nil), sample...)
		binary.BigEndian.PutUint32(legacySample[tokenOff:epochOff], p.legacyBindingToken)
		if err := p.track.WriteSample(media.Sample{Data: legacySample, Duration: time.Millisecond}); err != nil {
			logger.Infof("vp8channel: legacy WriteSample failed: %v", err)
		} else {
			p.outFrames.Add(1)
			p.outBytes.Add(uint64(len(legacySample)))
		}
	}
	p.maybeLogStats()
	return now
}

func (p *streamTransport) buildIdleFrame() []byte {
	hdr := p.epochHeader()
	frame := make([]byte, epochHdrLen+10)
	copy(frame, hdr[:])
	binary.BigEndian.PutUint32(frame[epochHdrLen:epochHdrLen+4], batchMagic)
	binary.BigEndian.PutUint16(frame[epochHdrLen+4:epochHdrLen+6], 0)
	binary.BigEndian.PutUint32(frame[epochHdrLen+6:epochHdrLen+10], uint32(p.idleNonce.Add(1)))
	return frame
}

func (p *streamTransport) maybeLogStats() {
	now := time.Now().Unix()
	prev := p.lastStats.Load()
	if now-prev < 10 || !p.lastStats.CompareAndSwap(prev, now) {
		return
	}
	var directSent, directRecv, directQueued uint64
	var sctpCwnd, sctpRwnd uint32
	var sctpSRTT float64
	directUp := false
	if path := p.direct.Load(); path != nil {
		directSent, directRecv = path.Stats()
		directUp = path.Healthy()
		directQueued = path.Queued()
		sctpCwnd, sctpRwnd, sctpSRTT = path.SCTPInfo()
	}
	var srtt int32
	p.kcpMu.RLock()
	if rt := p.kcp; rt != nil {
		srtt = rt.sess.GetSRTT()
	}
	p.kcpMu.RUnlock()
	// KCP counters are process-wide; one tunnel per process in practice.
	snmp := kcp.DefaultSnmp.Copy()
	logger.Infof(
		"vp8channel stats: out_frames=%d out_bytes=%d in_frames=%d in_bytes=%d outbound_queue=%d/%d direct=%v direct_out=%d direct_in=%d kcp_out=%d kcp_retrans=%d kcp_fast=%d kcp_lost=%d kcp_dup=%d kcp_srtt=%dms direct_queued=%d sctp_cwnd=%d sctp_rwnd=%d sctp_srtt=%.0fms cc_wnd=%d",
		p.outFrames.Load(),
		p.outBytes.Load(),
		p.inFrames.Load(),
		p.inBytes.Load(),
		len(p.outbound),
		cap(p.outbound),
		directUp, directSent, directRecv,
		snmp.OutSegs, snmp.RetransSegs, snmp.FastRetransSegs, snmp.LostSegs, snmp.RepeatSegs,
		srtt, directQueued, sctpCwnd, sctpRwnd, sctpSRTT, p.ccWnd.Load(),
	)
}

func (p *streamTransport) collectOutboundBatch() [][]byte {
	limit := p.dynamicBatchLimit()
	frames := make([][]byte, 0, limit)
	size := epochHdrLen + 6

	// add appends frame unless doing so would push the sample past
	// maxSampleBytes; a lone frame is always accepted.
	add := func(frame []byte) bool {
		next := size + 2 + len(frame) - epochHdrLen
		if len(frames) > 0 && p.maxSampleBytes > 0 && next > p.maxSampleBytes {
			return false
		}
		frames = append(frames, frame)
		size = next
		return true
	}

	p.pendingMu.Lock()
	pending := p.pending
	p.pending = nil
	p.pendingMu.Unlock()
	if pending != nil {
		add(pending)
	}

	for len(frames) < limit {
		select {
		case frame := <-p.outbound:
			if !add(frame) {
				p.pendingMu.Lock()
				p.pending = frame
				p.pendingMu.Unlock()
				return frames
			}
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

// resetForNewPeerSession replaces KCP after the peer started a new session
// and makes the upper layer reinstall its smux session before any frame of
// the new session is delivered. KCP alone is not enough: the old smux
// session keeps the previous peer's stream IDs and flow-control state, so
// the new peer's streams were accepted but never answered (every Wi-Fi/LTE
// switch wedged the tunnel until a full restart). Runs synchronously on the
// ingress goroutine on purpose: data delivered into the old smux session
// before the swap would be acknowledged by KCP and lost.
func (p *streamTransport) resetForNewPeerSession() {
	p.resetKCP()
	p.reconnectMu.Lock()
	cb := p.reconnectFn
	p.reconnectMu.Unlock()
	if cb != nil {
		cb()
	}
}

func (p *streamTransport) newKCP() (*kcpRuntime, error) {
	rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
	if err != nil {
		return nil, err
	}
	rt.conn.setRoute(p.trySendDirect)
	return rt, nil
}

// AttachDirectPath routes KCP packets over a direct data channel while it is
// healthy. Frames arriving on it go through the same token/epoch checks as
// conference frames, so a stale path cannot inject into a newer session.
func (p *streamTransport) AttachDirectPath(path *directpath.Path) {
	path.OnFrame(func(frame []byte) {
		if len(frame) >= epochHdrLen {
			p.handleIncomingFrame(frame)
		}
	})
	if old := p.direct.Swap(path); old != nil && old != path {
		old.Close()
	}
	logger.Infof("vp8channel: direct path attached")
	go p.runDirectCC(path)
	go func() {
		<-path.Done()
		if p.direct.CompareAndSwap(path, nil) {
			logger.Infof("vp8channel: direct path closed; using conference path")
		}
	}()
}

// DirectPathActive reports whether a healthy direct path is attached.
func (p *streamTransport) DirectPathActive() bool { return p.direct.Load().Healthy() }

func (p *streamTransport) trySendDirect(frame []byte) bool {
	path := p.direct.Load()
	if path == nil || !path.Healthy() {
		return false
	}
	if p.serverRole {
		p.stampServedEpoch(frame)
	}
	if !path.Send(frame) {
		return false
	}
	p.outFrames.Add(1)
	p.outBytes.Add(uint64(len(frame)))
	p.directOutBytes.Add(uint64(len(frame)))
	return true
}

func (p *streamTransport) setLocalEpoch(epoch uint32) {
	p.ownEpochs.Store(epoch, struct{}{})
	p.localEpoch.Store(epoch)
}

func (p *streamTransport) isOwnEpoch(epoch uint32) bool {
	_, own := p.ownEpochs.Load(epoch)
	return own
}

// startNewLocalSession gives this side a fresh epoch after its own carrier
// reconnected (for example iOS rejoining Telemost after a Wi-Fi/LTE switch).
// The local KCP is about to restart from sequence zero; under the old epoch
// the peer kept its KCP and silently discarded the new segments as
// duplicates, so the tunnel stayed dead. A new epoch makes the peer adopt the
// session after its ingress-idle window and rebuild its KCP and smux state.
// Only a local carrier reconnect bumps the epoch, never a peer-triggered
// reset, so the two sides cannot reset each other in a loop.
func (p *streamTransport) startNewLocalSession() {
	prev := p.localEpoch.Load()
	next := randomEpoch()
	for next == prev || p.isOwnEpoch(next) {
		next = randomEpoch()
	}
	p.setLocalEpoch(next)
	logger.Infof("vp8channel: local carrier reconnected; new local session epoch prev=0x%08x next=0x%08x", prev, next)
}

func (p *streamTransport) resetKCP() {
	p.kcpMu.Lock()
	old := p.kcp
	p.kcp = nil
	p.kcpMu.Unlock()
	if old != nil {
		old.close()
	}
	// Drain after closing so the old session cannot queue more packets that
	// would go out stamped for the new peer session.
	p.drainOutbound()
	// Note: localEpoch is intentionally NOT bumped here. The epoch is a
	// per-process identifier set once in New(). If we changed it on every
	// peer-triggered reset, the peer would see a "new" epoch from us, reset
	// itself, send back its (unchanged) epoch which we'd then see as "new"
	// again - and the two sides would loop forever tearing down smux.
	rt, err := p.newKCP()
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

	// Telemost can expose multiple VP8 tracks for the same participant across
	// reconnects/SFU churn. Read and deliver all valid frames; token, self-echo,
	// and epoch handling below decide whether a frame belongs to the peer. A
	// single-active-track gate can freeze ingress when Telemost leaves that track
	// quiet while another track still carries the peer's KCP traffic.
	go p.readVP8Track(track)
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

func (p *streamTransport) readVP8Track(track *webrtc.TrackRemote) {
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
		p.handleIncomingFrame(frame)
	}
}

func (p *streamTransport) handleFirstPeer(peerEpoch uint32) {
	p.peerEpoch.Store(peerEpoch)
	p.firstPeerAt.Store(time.Now().UnixNano())
	logger.Infof("vp8channel: peer first seen epoch=0x%08x", peerEpoch)
	p.kcpOnce.Do(func() {
		rt, err := p.newKCP()
		if err != nil {
			logger.Infof("vp8channel: startKCP failed: %v", err)
			return
		}
		p.kcpMu.Lock()
		p.kcp = rt
		p.kcpMu.Unlock()
		logger.Infof("vp8channel: KCP started localEpoch=0x%08x", p.localEpoch.Load())
	})
}

// handleIncomingFrame parses the epoch header and either delivers the KCP
// payload to the local session or triggers a reset when the peer's epoch
// changes (peer process restart).
func (p *streamTransport) handleIncomingFrame(frame []byte) {
	frameToken := binary.BigEndian.Uint32(frame[tokenOff:epochOff])
	expectedToken := p.expectedPeerBindingToken()
	isDirectional := frameToken == expectedToken
	isLegacy := p.publishLegacy && frameToken == p.legacyBindingToken
	if !isDirectional && (!isLegacy || p.directionalPeerSeen.Load()) {
		logger.Debugf("vp8channel: frame token mismatch got=0x%08x want=0x%08x (foreign client or noise)",
			frameToken, expectedToken)
		return
	}
	if p.servedOtherSession(frame) {
		logger.Debugf("vp8channel: dropping server frame addressed to a previous client session")
		return
	}
	peerEpoch := binary.BigEndian.Uint32(frame[epochOff:epochHdrLen])
	kcpPayload := frame[epochHdrLen:]
	// A directional frame is authoritative. If a legacy/self/stale frame won the
	// startup race, atomically move the session to the real directional peer and
	// permanently reject legacy ingress for this process.
	if p.publishLegacy && isDirectional && p.directionalPeerSeen.CompareAndSwap(false, true) && p.hadPeer.Load() && p.peerWireToken.Load() != expectedToken {
		prev := p.peerEpoch.Swap(peerEpoch)
		p.peerWireToken.Store(expectedToken)
		p.retiredPeerEpochs.Store(prev, struct{}{})
		p.lastEpochReset.Store(time.Now().UnixNano())
		logger.Infof("vp8channel: peer upgraded from legacy to directional token prev=0x%08x next=0x%08x - resetting KCP", prev, peerEpoch)
		p.resetKCP()
	}
	// Some carriers/SFUs reflect our own published VP8 track back to us as a
	// remote track. Those frames carry our local epoch, not the peer's. If we
	// treat them as peer traffic, epoch tracking toggles between "self" and
	// "peer" and both sides loop forever resetting smux/KCP.
	if p.isOwnEpoch(peerEpoch) {
		logger.Debugf("vp8channel: self-echo detected epoch=0x%08x (SFU reflects our own track)", peerEpoch)
		return
	}

	if !p.hadPeer.Swap(true) {
		p.peerWireToken.Store(frameToken)
		p.handleFirstPeer(peerEpoch)
	} else if prev := p.peerEpoch.Load(); prev != peerEpoch {
		// Telemost/SFU can briefly forward a stale VP8 track when a participant
		// with the same identity reconnects. During the initial convergence
		// window we adopt the newest epoch without resetting KCP; otherwise the
		// first HTTP stream is torn down before smux has a chance to settle.
		now := time.Now().UnixNano()
		if first := p.firstPeerAt.Load(); first != 0 && time.Duration(now-first) < 10*time.Second {
			if !p.initialPeerPromoted.Swap(true) && p.promotePeerEpoch(prev, peerEpoch) {
				logger.Infof(
					"vp8channel: peer epoch promoted during initial grace prev=0x%08x next=0x%08x - resetting KCP",
					prev,
					peerEpoch,
				)
				p.lastEpochReset.Store(now)
				p.resetKCP()
			} else {
				// Once the current SFU track has been promoted, frames from the
				// previously selected stale epoch must not enter the new KCP runtime.
				return
			}
		} else if reconnectAt := p.localReconnectAt.Swap(0); reconnectAt > p.lastIngressAt.Load() {
			// The carrier already replaced KCP. Reuse that session only if
			// no peer traffic has arrived since the reconnect.
			if p.promotePeerEpoch(prev, peerEpoch) {
				logger.Infof("vp8channel: peer epoch accepted after local reconnect prev=0x%08x next=0x%08x - keeping fresh KCP", prev, peerEpoch)
			}
		} else if hadIngress := p.inFrames.Load() > 0; p.peerIngressIdle(now) {
			// A long-lived server peer can retain a stale client track after Stop.
			// When the next client process joins with a new epoch, keeping the old
			// KCP runtime makes the handshake permanently incompatible. Promote only
			// after selected-peer ingress has been idle; a live session therefore
			// cannot be stolen by late SFU/reflected-track churn.
			if p.promotePeerEpoch(prev, peerEpoch) {
				logger.Infof("vp8channel: peer epoch promoted after ingress idle prev=0x%08x next=0x%08x - resetting KCP", prev, peerEpoch)
				p.lastEpochReset.Store(now)
				if hadIngress {
					p.resetForNewPeerSession()
				} else {
					p.resetKCP()
				}
			}
		} else {
			return
		}
	}
	if peerEpoch != p.peerEpoch.Load() {
		return
	}

	if len(kcpPayload) == 0 {
		return
	}
	if len(kcpPayload) >= 6 && binary.BigEndian.Uint32(kcpPayload[0:4]) == batchMagic {
		if binary.BigEndian.Uint16(kcpPayload[4:6]) == 0 {
			p.markIdleIngress()
			return
		}
		p.handleIncomingBatch(kcpPayload)
		return
	}
	p.deliverKCPPacket(kcpPayload)
}

func (p *streamTransport) peerIngressIdle(now int64) bool {
	if p.inFrames.Load() == 0 {
		return true
	}
	lastIngressAt := p.lastIngressAt.Load()
	return lastIngressAt == 0 || time.Duration(now-lastIngressAt) >= peerIngressIdlePeriod
}

func (p *streamTransport) promotePeerEpoch(prev uint32, next uint32) bool {
	if _, retired := p.retiredPeerEpochs.Load(next); retired {
		return false
	}
	if !p.peerEpoch.CompareAndSwap(prev, next) {
		return false
	}
	p.retiredPeerEpochs.Store(prev, struct{}{})
	return true
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

// markIdleIngress records a keepalive from the selected peer. smux keepalives
// are disabled, so an idle but healthy session carries no KCP packets at all;
// without counting keepalives the server watchdog reads an idle session as
// frozen ingress and restarts olcrtc, which strands the connected client.
func (p *streamTransport) markIdleIngress() {
	p.lastIngressAt.Store(time.Now().UnixNano())
	p.inFrames.Add(1)
	p.maybeLogStats()
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
