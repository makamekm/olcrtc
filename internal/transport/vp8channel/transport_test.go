package vp8channel

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func pumpPackets(stop <-chan struct{}, from <-chan []byte, to *kcpRuntime) {
	for {
		select {
		case <-stop:
			return
		case pkt := <-from:
			// Strip the on-wire epoch header that kcpConn prepends;
			// the real receive path does this before calling deliver().
			if len(pkt) > epochHdrLen {
				to.deliver(pkt[epochHdrLen:])
			}
		}
	}
}

func checkMessages(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d", len(got), len(want))
	}
	for i, m := range want {
		if !bytes.Equal(got[i], m) {
			t.Errorf("msg %d mismatch: got %d bytes, want %d", i, len(got[i]), len(m))
		}
	}
}

func buildReceiver(n int) (func([]byte), <-chan struct{}, func() [][]byte) {
	var mu sync.Mutex
	var recv [][]byte
	done := make(chan struct{})
	cb := func(msg []byte) {
		mu.Lock()
		recv = append(recv, append([]byte(nil), msg...))
		count := len(recv)
		mu.Unlock()
		if count == n {
			close(done)
		}
	}
	get := func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return recv
	}
	return cb, done, get
}

// TestKCPLoopback runs two KCP runtimes back-to-back through an in-memory
// pipe simulating a perfect carrier. Verifies that messages survive the
// KCP layer with their boundaries intact.
func TestKCPLoopback(t *testing.T) {
	msgs := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte("x"), 1000),
		bytes.Repeat([]byte("y"), 20000),
	}

	a2b := make(chan []byte, 256)
	b2a := make(chan []byte, 256)

	cb, doneB, getRecv := buildReceiver(len(msgs))

	rtA, err := startKCP(a2b, nil, testEpochHdr(1))
	if err != nil {
		t.Fatalf("startKCP A: %v", err)
	}
	defer rtA.close()

	rtB, err := startKCP(b2a, cb, testEpochHdr(2))
	if err != nil {
		t.Fatalf("startKCP B: %v", err)
	}
	defer rtB.close()

	stop := make(chan struct{})
	defer close(stop)

	go pumpPackets(stop, a2b, rtB)
	go pumpPackets(stop, b2a, rtA)

	for _, m := range msgs {
		if err := rtA.send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	select {
	case <-doneB:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for messages")
	}

	checkMessages(t, getRecv(), msgs)
}

func TestVP8KeepaliveDoesNotLookLikeKCP(t *testing.T) {
	if len(vp8Keepalive) != tokenOff {
		t.Errorf("vp8Keepalive length %d != tokenOff %d", len(vp8Keepalive), tokenOff)
	}
}

func TestDynamicBatchLimitRaisesOnlyUnderBackpressure(t *testing.T) {
	tr := &streamTransport{
		batchSize: 16,
		outbound:  make(chan []byte, outboundQueueSize),
	}
	if got := tr.dynamicBatchLimit(); got != 16 {
		t.Fatalf("empty queue dynamicBatchLimit() = %d, want 16", got)
	}
	for i := 0; i < cap(tr.outbound)/4; i++ {
		tr.outbound <- []byte{0x01}
	}
	if got := tr.dynamicBatchLimit(); got != 32 {
		t.Fatalf("quarter queue dynamicBatchLimit() = %d, want 32", got)
	}
	for i := len(tr.outbound); i < cap(tr.outbound)/2; i++ {
		tr.outbound <- []byte{0x01}
	}
	if got := tr.dynamicBatchLimit(); got != maxDynamicBatchSize {
		t.Fatalf("half queue dynamicBatchLimit() = %d, want %d", got, maxDynamicBatchSize)
	}
}

func testEpochHdr(epoch uint32) [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	copy(hdr[:], vp8Keepalive)
	binary.BigEndian.PutUint32(hdr[tokenOff:epochOff], bindingToken("test"))
	binary.BigEndian.PutUint32(hdr[epochOff:], epoch)
	return hdr
}

func TestHandleIncomingFrameIgnoresLoopedBackLocalEpoch(t *testing.T) {
	tr := &streamTransport{
		bindingToken: bindingToken("test"),
		localEpoch:   12345,
		onData:       func([]byte) {},
	}

	var called atomic.Int32
	tr.reconnectFn = func() { called.Add(1) }

	frame := make([]byte, epochHdrLen+4)
	copy(frame, vp8Keepalive)
	binary.BigEndian.PutUint32(frame[tokenOff:epochOff], tr.bindingToken)
	binary.BigEndian.PutUint32(frame[epochOff:], tr.localEpoch)
	copy(frame[epochHdrLen:], []byte{1, 2, 3, 4})

	tr.handleIncomingFrame(frame)

	if tr.hadPeer.Load() {
		t.Fatal("self-echo frame must not mark peer as seen")
	}
	if got := tr.peerEpoch.Load(); got != 0 {
		t.Fatalf("peer epoch changed on self-echo: got %d want 0", got)
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("reconnect called on self-echo: got %d want 0", got)
	}
}

func TestHandleIncomingFrameIgnoresForeignBindingToken(t *testing.T) {
	tr := &streamTransport{
		bindingToken: bindingToken("srv-client"),
		localEpoch:   12345,
		onData:       func([]byte) {},
	}

	var called atomic.Int32
	tr.reconnectFn = func() { called.Add(1) }

	frame := make([]byte, epochHdrLen+4)
	copy(frame, vp8Keepalive)
	binary.BigEndian.PutUint32(frame[tokenOff:epochOff], bindingToken("other-client"))
	binary.BigEndian.PutUint32(frame[epochOff:], 999)
	copy(frame[epochHdrLen:], []byte{1, 2, 3, 4})

	tr.handleIncomingFrame(frame)

	if tr.hadPeer.Load() {
		t.Fatal("foreign frame must not mark peer as seen")
	}
	if got := tr.peerEpoch.Load(); got != 0 {
		t.Fatalf("peer epoch changed on foreign frame: got %d want 0", got)
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("reconnect called on foreign frame: got %d want 0", got)
	}
}

func TestZeroIngressEpochChangePromotesPeerAndResetsKCP(t *testing.T) {
	out := make(chan []byte, 16)
	rt, err := startKCP(out, func([]byte) {}, testEpochHdr(111))
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}

	tr := &streamTransport{
		bindingToken: bindingToken("test"),
		localEpoch:   111,
		outbound:     out,
		kcp:          rt,
	}
	tr.hadPeer.Store(true)
	tr.peerEpoch.Store(222)
	tr.firstPeerAt.Store(time.Now().Add(-30 * time.Second).UnixNano())

	var called atomic.Int32
	tr.reconnectFn = func() { called.Add(1) }

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 333, nil))

	if got := tr.peerEpoch.Load(); got != 333 {
		t.Fatalf("peer epoch = %d, want 333", got)
	}
	if got := tr.lastEpochReset.Load(); got == 0 {
		t.Fatal("lastEpochReset was not recorded during zero-ingress promotion")
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("reconnect called during zero ingress: got %d want 0", got)
	}
	tr.kcpMu.RLock()
	newKCP := tr.kcp
	reset := newKCP != rt
	tr.kcpMu.RUnlock()
	if !reset {
		t.Fatal("zero-ingress epoch change kept stale KCP")
	}
	defer newKCP.close()
}

func TestIdlePostIngressEpochChangePromotesPeerAndResetsKCP(t *testing.T) {
	out := make(chan []byte, 16)
	rt, err := startKCP(out, func([]byte) {}, testEpochHdr(111))
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}
	tr := &streamTransport{
		bindingToken: bindingToken("test"),
		localEpoch:   111,
		outbound:     out,
		kcp:          rt,
	}
	tr.hadPeer.Store(true)
	tr.peerEpoch.Store(222)
	tr.firstPeerAt.Store(time.Now().Add(-30 * time.Second).UnixNano())
	tr.inFrames.Store(10)
	tr.lastIngressAt.Store(time.Now().Add(-peerIngressIdlePeriod).Add(-time.Second).UnixNano())

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 333, nil))

	if got := tr.peerEpoch.Load(); got != 333 {
		t.Fatalf("idle peer epoch = %d, want 333", got)
	}
	tr.kcpMu.RLock()
	newKCP := tr.kcp
	reset := newKCP != rt
	tr.kcpMu.RUnlock()
	if !reset {
		t.Fatal("idle post-ingress epoch change kept stale KCP")
	}
	defer newKCP.close()
}

func TestPostIngressEpochChangeKeepsKCP(t *testing.T) {
	out := make(chan []byte, 16)
	rt, err := startKCP(out, func([]byte) {}, testEpochHdr(111))
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}
	defer rt.close()

	tr := &streamTransport{
		bindingToken: bindingToken("test"),
		localEpoch:   111,
		outbound:     out,
		kcp:          rt,
	}
	tr.hadPeer.Store(true)
	tr.peerEpoch.Store(222)
	tr.firstPeerAt.Store(time.Now().Add(-30 * time.Second).UnixNano())
	tr.inFrames.Store(1)
	tr.lastIngressAt.Store(time.Now().UnixNano())

	var called atomic.Int32
	tr.reconnectFn = func() { called.Add(1) }

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 333, nil))

	if got := tr.peerEpoch.Load(); got != 222 {
		t.Fatalf("active peer epoch was replaced: got %d want 222", got)
	}
	if got := tr.lastEpochReset.Load(); got != 0 {
		t.Fatalf("lastEpochReset updated after post-ingress epoch change: got %d want 0", got)
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("reconnect calls = %d, want 0", got)
	}
	tr.kcpMu.RLock()
	kept := tr.kcp == rt
	tr.kcpMu.RUnlock()
	if !kept {
		t.Fatal("post-ingress epoch change reset KCP")
	}
}

func TestInitialGracePromotesOneEpochResetsKCPAndRejectsStaleFrames(t *testing.T) {
	out := make(chan []byte, 32)
	tr := &streamTransport{
		bindingToken: bindingToken("test"),
		localEpoch:   111,
		outbound:     out,
		onData:       func([]byte) {},
	}

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 222, nil))
	tr.kcpMu.RLock()
	firstKCP := tr.kcp
	tr.kcpMu.RUnlock()
	if firstKCP == nil {
		t.Fatal("first peer did not start KCP")
	}

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 333, nil))
	tr.kcpMu.RLock()
	promotedKCP := tr.kcp
	tr.kcpMu.RUnlock()
	defer promotedKCP.close()
	if promotedKCP == firstKCP {
		t.Fatal("initial epoch promotion did not reset KCP")
	}
	if got := tr.peerEpoch.Load(); got != 333 {
		t.Fatalf("promoted peer epoch = %d, want 333", got)
	}

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 222, []byte{1, 2, 3, 4}))
	if got := tr.peerEpoch.Load(); got != 333 {
		t.Fatalf("stale epoch replaced promoted epoch: got %d want 333", got)
	}
	tr.kcpMu.RLock()
	keptKCP := tr.kcp
	tr.kcpMu.RUnlock()
	if keptKCP != promotedKCP {
		t.Fatal("stale epoch reset promoted KCP")
	}

	tr.firstPeerAt.Store(time.Now().Add(-30 * time.Second).UnixNano())
	tr.lastIngressAt.Store(time.Now().Add(-peerIngressIdlePeriod).Add(-time.Second).UnixNano())
	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 222, nil))
	if got := tr.peerEpoch.Load(); got != 333 {
		t.Fatalf("retired epoch was reselected after idle: got %d want 333", got)
	}
	tr.kcpMu.RLock()
	keptKCP = tr.kcp
	tr.kcpMu.RUnlock()
	if keptKCP != promotedKCP {
		t.Fatal("retired epoch reset KCP after idle")
	}
}

func TestDirectionalBindingTokensAcceptOnlyOppositeRole(t *testing.T) {
	clientOut, clientPeer := directionalBindingTokens("u-makame-device-1@1700000000000")
	serverOut, serverPeer := directionalBindingTokens("srv-u-makame-device-1")
	if clientOut == serverOut {
		t.Fatal("client and server outbound binding tokens must differ")
	}
	if clientOut != serverPeer {
		t.Fatalf("server peer token = 0x%08x, want client outbound 0x%08x", serverPeer, clientOut)
	}
	if serverOut != clientPeer {
		t.Fatalf("client peer token = 0x%08x, want server outbound 0x%08x", clientPeer, serverOut)
	}

	tr := &streamTransport{
		bindingToken:     clientOut,
		peerBindingToken: clientPeer,
		localEpoch:       111,
		outbound:         make(chan []byte, 8),
		onData:           func([]byte) {},
	}
	tr.handleIncomingFrame(testVP8Frame(t, clientOut, 222, nil))
	if tr.hadPeer.Load() {
		t.Fatal("reflected client frame was accepted as peer traffic")
	}
	tr.handleIncomingFrame(testVP8Frame(t, serverOut, 333, nil))
	if !tr.hadPeer.Load() || tr.peerEpoch.Load() != 333 {
		t.Fatalf("server frame was not accepted: hadPeer=%v epoch=%d", tr.hadPeer.Load(), tr.peerEpoch.Load())
	}
	tr.kcpMu.RLock()
	rt := tr.kcp
	tr.kcpMu.RUnlock()
	if rt == nil {
		t.Fatal("accepted server frame did not start KCP")
	}
	rt.close()
}

func TestServerLegacyFallbackUpgradesPermanentlyToDirectionalPeer(t *testing.T) {
	serverOut, serverPeer := directionalBindingTokens("srv-u-makame-device-1")
	legacy := bindingToken("u-makame-device-1")
	tr := &streamTransport{
		bindingToken:       serverOut,
		peerBindingToken:   serverPeer,
		legacyBindingToken: legacy,
		publishLegacy:      true,
		localEpoch:         111,
		outbound:           make(chan []byte, 8),
		onData:             func([]byte) {},
	}

	tr.handleIncomingFrame(testVP8Frame(t, legacy, 222, nil))
	if tr.peerEpoch.Load() != 222 || tr.peerWireToken.Load() != legacy {
		t.Fatalf("legacy peer not accepted: epoch=%d token=0x%08x", tr.peerEpoch.Load(), tr.peerWireToken.Load())
	}
	tr.kcpMu.RLock()
	legacyKCP := tr.kcp
	tr.kcpMu.RUnlock()

	tr.handleIncomingFrame(testVP8Frame(t, serverPeer, 333, nil))
	if !tr.directionalPeerSeen.Load() || tr.peerEpoch.Load() != 333 || tr.peerWireToken.Load() != serverPeer {
		t.Fatalf("directional upgrade failed: seen=%v epoch=%d token=0x%08x", tr.directionalPeerSeen.Load(), tr.peerEpoch.Load(), tr.peerWireToken.Load())
	}
	tr.kcpMu.RLock()
	directionalKCP := tr.kcp
	tr.kcpMu.RUnlock()
	if directionalKCP == nil || directionalKCP == legacyKCP {
		t.Fatal("directional upgrade did not reset KCP")
	}

	tr.handleIncomingFrame(testVP8Frame(t, legacy, 444, nil))
	if tr.peerEpoch.Load() != 333 {
		t.Fatalf("legacy frame replaced directional peer: epoch=%d", tr.peerEpoch.Load())
	}
	directionalKCP.close()
}

func testVP8Frame(t *testing.T, token uint32, epoch uint32, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, epochHdrLen+len(payload))
	copy(frame, vp8Keepalive)
	binary.BigEndian.PutUint32(frame[tokenOff:epochOff], token)
	binary.BigEndian.PutUint32(frame[epochOff:], epoch)
	copy(frame[epochHdrLen:], payload)
	return frame
}

func testKCPFrame(t *testing.T, payloadLen int, fill byte) []byte {
	t.Helper()
	return append(make([]byte, epochHdrLen), bytes.Repeat([]byte{fill}, payloadLen)...)
}

func batchSampleSize(frames [][]byte) int {
	if len(frames) == 1 {
		return len(frames[0])
	}
	size := epochHdrLen + 6
	for _, frame := range frames {
		size += 2 + len(frame) - epochHdrLen
	}
	return size
}

func TestCollectOutboundBatchKeepsSampleInOneRTPPacket(t *testing.T) {
	tr := &streamTransport{
		batchSize:      32,
		maxSampleBytes: defaultMaxSampleBytes,
		outbound:       make(chan []byte, 32),
	}
	for i := range 5 {
		tr.outbound <- testKCPFrame(t, 400, byte(i))
	}

	var sent [][]byte
	for range 5 {
		batch := tr.collectOutboundBatch()
		if len(batch) == 0 {
			break
		}
		if size := batchSampleSize(batch); size > defaultMaxSampleBytes {
			t.Fatalf("sample size = %d, want <= %d", size, defaultMaxSampleBytes)
		}
		sent = append(sent, batch...)
	}
	if len(sent) != 5 {
		t.Fatalf("sent %d frames, want 5 (deferred frame lost?)", len(sent))
	}
	for i, frame := range sent {
		if frame[epochHdrLen] != byte(i) {
			t.Fatalf("frame %d out of order: fill=%d", i, frame[epochHdrLen])
		}
	}
}

func TestCollectOutboundBatchSendsOversizedFrameAlone(t *testing.T) {
	tr := &streamTransport{
		batchSize:      32,
		maxSampleBytes: 200,
		outbound:       make(chan []byte, 4),
	}
	tr.outbound <- testKCPFrame(t, 500, 1)
	tr.outbound <- testKCPFrame(t, 10, 2)

	if batch := tr.collectOutboundBatch(); len(batch) != 1 || batch[0][epochHdrLen] != 1 {
		t.Fatalf("first batch = %d frames, want the oversized frame alone", len(batch))
	}
	if batch := tr.collectOutboundBatch(); len(batch) != 1 || batch[0][epochHdrLen] != 2 {
		t.Fatalf("second batch = %d frames, want the deferred small frame", len(batch))
	}
}

func TestDrainOutboundDropsDeferredFrame(t *testing.T) {
	tr := &streamTransport{
		batchSize:      32,
		maxSampleBytes: 100,
		outbound:       make(chan []byte, 4),
	}
	tr.outbound <- testKCPFrame(t, 60, 1)
	tr.outbound <- testKCPFrame(t, 60, 2)
	if batch := tr.collectOutboundBatch(); len(batch) != 1 {
		t.Fatalf("batch = %d frames, want 1", len(batch))
	}

	tr.drainOutbound()

	if batch := tr.collectOutboundBatch(); len(batch) != 0 {
		t.Fatalf("frame from a reset KCP session survived drain: %d frames", len(batch))
	}
}

func TestIdleKeepaliveFromPeerCountsAsIngress(t *testing.T) {
	out, peer := directionalBindingTokens("srv-u-device-1")
	tr := &streamTransport{
		bindingToken:     out,
		peerBindingToken: peer,
		localEpoch:       111,
		outbound:         make(chan []byte, 8),
		onData:           func([]byte) {},
	}
	defer func() {
		tr.kcpMu.RLock()
		rt := tr.kcp
		tr.kcpMu.RUnlock()
		if rt != nil {
			rt.close()
		}
	}()

	idle := make([]byte, 10)
	binary.BigEndian.PutUint32(idle[0:4], batchMagic)
	binary.BigEndian.PutUint32(idle[6:10], 7)

	tr.handleIncomingFrame(testVP8Frame(t, peer, 222, idle))
	tr.handleIncomingFrame(testVP8Frame(t, peer, 222, idle))

	if got := tr.inFrames.Load(); got != 2 {
		t.Fatalf("inFrames = %d, want 2: idle keepalives must keep the watchdog from restarting an idle session", got)
	}
	if got := tr.inBytes.Load(); got != 0 {
		t.Fatalf("inBytes = %d, want 0 for keepalives", got)
	}
	if tr.lastIngressAt.Load() == 0 {
		t.Fatal("lastIngressAt not updated by keepalive")
	}
}

func TestSampleIntervalUsesPacingFloorForLegacyTokenFPS(t *testing.T) {
	floor := time.Second / minSamplesPerSecond
	for _, fps := range []int{25, 60} {
		if got := sampleInterval(fps); got != floor {
			t.Fatalf("sampleInterval(%d) = %v, want %v", fps, got, floor)
		}
	}
	if got := sampleInterval(2000); got != time.Second/2000 {
		t.Fatalf("sampleInterval(2000) = %v, want %v", got, time.Second/2000)
	}
}

func TestMarkFrameTypeSendsOneKeyframePerInterval(t *testing.T) {
	tr := &streamTransport{keyframeInterval: time.Second}
	start := time.Now()
	frame := func(at time.Time) byte {
		sample := append([]byte(nil), vp8Keepalive...)
		tr.markFrameType(sample, at)
		return sample[0] & 0x01
	}
	if got := frame(start); got != 0 {
		t.Fatalf("first sample must be a keyframe, frame-type bit=%d", got)
	}
	if got := frame(start.Add(500 * time.Millisecond)); got != 1 {
		t.Fatalf("sample inside interval must be an interframe, frame-type bit=%d", got)
	}
	if got := frame(start.Add(time.Second)); got != 0 {
		t.Fatalf("sample after interval must be a keyframe, frame-type bit=%d", got)
	}
}

func TestMarkFrameTypeDisabledKeepsKeyframes(t *testing.T) {
	tr := &streamTransport{}
	sample := append([]byte(nil), vp8Keepalive...)
	tr.markFrameType(sample, time.Now())
	tr.markFrameType(sample, time.Now())
	if sample[0]&0x01 != 0 {
		t.Fatal("disabled marking must leave keyframes untouched")
	}
}

func TestServerStampsServedClientEpoch(t *testing.T) {
	srv := &streamTransport{serverRole: true}
	srv.peerEpoch.Store(0xabcdef01)
	sample := testVP8Frame(t, 1, 2, []byte("kcp"))
	srv.stampServedEpoch(sample)

	cli := &streamTransport{localEpoch: 0xabcdef01}
	if cli.servedOtherSession(sample) {
		t.Fatal("client dropped a frame served for its own session")
	}
	cli.localEpoch = 0x12345678
	if !cli.servedOtherSession(sample) {
		t.Fatal("client accepted a frame the server sent to a previous client session")
	}
	if binary.BigEndian.Uint32(sample[tokenOff:epochOff]) != 1 || binary.BigEndian.Uint32(sample[epochOff:epochHdrLen]) != 2 {
		t.Fatal("served-epoch stamp overwrote the token or epoch")
	}
}

func TestUnstampedServerFramesStayAccepted(t *testing.T) {
	cli := &streamTransport{localEpoch: 0x12345678}
	if cli.servedOtherSession(testVP8Frame(t, 1, 2, nil)) {
		t.Fatal("frames from servers without the served-epoch stamp must be accepted")
	}
	srv := &streamTransport{serverRole: true}
	if srv.servedOtherSession(testVP8Frame(t, 1, 2, nil)) {
		t.Fatal("server must not filter client frames")
	}
}

func TestClientDropsStaleServerSessionFrames(t *testing.T) {
	out := make(chan []byte, 16)
	rt, err := startKCP(out, func([]byte) {}, testEpochHdr(111))
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}
	defer rt.close()
	cli := &streamTransport{
		bindingToken:     bindingToken("test"),
		peerBindingToken: bindingToken("test"),
		outbound:         out,
		kcp:              rt,
		localEpoch:       111,
	}
	srv := &streamTransport{serverRole: true}
	srv.peerEpoch.Store(99) // still serving the client's previous process
	stale := testVP8Frame(t, cli.expectedPeerBindingToken(), 222, nil)
	srv.stampServedEpoch(stale)

	cli.handleIncomingFrame(stale)

	if cli.hadPeer.Load() || cli.inFrames.Load() != 0 {
		t.Fatal("client adopted a server session that was serving its previous process")
	}
}

func TestNewPeerSessionReinstallsUpperSession(t *testing.T) {
	out := make(chan []byte, 16)
	rt, err := startKCP(out, func([]byte) {}, testEpochHdr(111))
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}
	tr := &streamTransport{
		bindingToken: bindingToken("test"),
		outbound:     out,
		kcp:          rt,
		localEpoch:   111,
	}
	tr.hadPeer.Store(true)
	tr.peerEpoch.Store(222)
	tr.firstPeerAt.Store(time.Now().Add(-30 * time.Second).UnixNano())
	tr.inFrames.Store(10)
	tr.lastIngressAt.Store(time.Now().Add(-peerIngressIdlePeriod).Add(-time.Second).UnixNano())
	var reinstalls atomic.Int32
	tr.reconnectFn = func() { reinstalls.Add(1) }

	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 333, nil))
	tr.handleIncomingFrame(testVP8Frame(t, tr.bindingToken, 333, nil))

	if got := reinstalls.Load(); got != 1 {
		t.Fatalf("upper session reinstalls = %d, want exactly 1 for one new peer session", got)
	}
	tr.kcpMu.RLock()
	defer tr.kcpMu.RUnlock()
	if tr.kcp != nil {
		tr.kcp.close()
	}
}
