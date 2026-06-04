package mobile

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryTun struct {
	reads  chan []byte
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newMemoryTun() *memoryTun {
	return &memoryTun{
		reads:  make(chan []byte, 8),
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
}

func (m *memoryTun) Read(dst []byte) (int, error) {
	select {
	case <-m.closed:
		return 0, io.ErrClosedPipe
	case packet := <-m.reads:
		return copy(dst, packet), nil
	}
}

func (m *memoryTun) Write(packet []byte) (int, error) {
	copyPacket := append([]byte(nil), packet...)
	select {
	case <-m.closed:
		return 0, io.ErrClosedPipe
	case m.writes <- copyPacket:
		return len(packet), nil
	}
}

func (m *memoryTun) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func TestAndroidTunReadWriterRejectsNonDNSUDPWithICMP(t *testing.T) {
	resetMobileGlobals(t)
	tun := newMemoryTun()
	rw := newAndroidTunReadWriter(tun, 1280, "127.0.0.1", 10808)

	packet := buildTestIPv4UDPPacket([4]byte{10, 8, 0, 2}, [4]byte{93, 184, 216, 34}, 55555, 443, []byte("quic"))
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1280)
		_, err := rw.Read(buf)
		errCh <- err
	}()

	tun.reads <- packet
	got := waitMemoryTunWrite(t, tun)
	if got[9] != 1 || got[20] != 3 || got[21] != 3 {
		t.Fatalf("response protocol/type/code = %d/%d/%d, want ICMP destination-port-unreachable", got[9], got[20], got[21])
	}
	if [4]byte(got[12:16]) != [4]byte{93, 184, 216, 34} || [4]byte(got[16:20]) != [4]byte{10, 8, 0, 2} {
		t.Fatalf("ICMP response src/dst = %v/%v, want original dst/src", got[12:16], got[16:20])
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != 1 {
		t.Fatalf("udpDropped = %d, want 1", dropped)
	}

	if err := rw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Read() after Close() error = %v, want io.ErrClosedPipe", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read() did not unblock after Close()")
	}
}

func TestPacketFlowReadWriterRejectsMediaUDP443WithICMP(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)

	packet := buildTestIPv4UDPPacket([4]byte{10, 8, 0, 2}, [4]byte{93, 184, 216, 34}, 55555, 443, []byte("quic"))
	if err := rw.Inject(packet); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	select {
	case got := <-rw.inbound:
		t.Fatalf("unexpected forwarded UDP/443 packet len=%d proto=%d", len(got), got[9])
	default:
	}
	select {
	case got := <-rw.outbound:
		if got[9] != 1 || got[20] != 3 || got[21] != 3 {
			t.Fatalf("response protocol/type/code = %d/%d/%d, want ICMP destination-port-unreachable", got[9], got[20], got[21])
		}
	case <-time.After(time.Second):
		t.Fatal("missing ICMP unreachable response for UDP/443")
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != 1 {
		t.Fatalf("udpDropped = %d, want 1", dropped)
	}
	if forwarded := atomic.LoadUint64(&rw.udpForwarded); forwarded != 0 {
		t.Fatalf("udpForwarded = %d, want 0", forwarded)
	}
	if in := atomic.LoadUint64(&rw.inPackets); in != 0 {
		t.Fatalf("inPackets = %d, want 0", in)
	}
}

func TestPacketFlowReadWriterRejectsRepeatedNonDNSUDPWithICMP(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)

	packet := buildTestIPv4UDPPacket([4]byte{10, 8, 0, 2}, [4]byte{93, 184, 216, 34}, 55555, 123, []byte("ntp"))
	for i := 0; i < 2; i++ {
		if err := rw.Inject(packet); err != nil {
			t.Fatalf("Inject(%d) error = %v", i, err)
		}
	}

	select {
	case got := <-rw.inbound:
		t.Fatalf("unexpected forwarded UDP packet len=%d proto=%d", len(got), got[9])
	default:
	}
	if icmpCount := drainICMPResponses(t, rw); icmpCount != 2 {
		t.Fatalf("ICMP responses for repeated UDP packets = %d, want 2", icmpCount)
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != 2 {
		t.Fatalf("udpDropped = %d, want 2", dropped)
	}
	if silent := atomic.LoadUint64(&rw.udpICMPSilent); silent != 0 {
		t.Fatalf("udpICMPSilent = %d, want 0", silent)
	}
	if in := atomic.LoadUint64(&rw.inPackets); in != 0 {
		t.Fatalf("inPackets = %d, want 0", in)
	}
}

func TestPacketFlowReadWriterRateLimitsUDPICMPFallbackPerWindow(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	totalFlows := packetFlowUDPICMPRejectWindowLimit + 4

	injectUniqueUDPFlows(t, rw, 0, totalFlows)

	icmpCount := drainICMPResponses(t, rw)
	if icmpCount != packetFlowUDPICMPRejectWindowLimit {
		t.Fatalf("first-window ICMP fallback responses = %d, want %d", icmpCount, packetFlowUDPICMPRejectWindowLimit)
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != uint64(totalFlows) {
		t.Fatalf("udpDropped = %d, want %d", dropped, totalFlows)
	}
	if rejected := atomic.LoadUint64(&rw.udpICMPRejected); rejected != uint64(packetFlowUDPICMPRejectWindowLimit) {
		t.Fatalf("udpICMPRejected = %d, want %d", rejected, packetFlowUDPICMPRejectWindowLimit)
	}
	if silent := atomic.LoadUint64(&rw.udpICMPSilent); silent != uint64(totalFlows-packetFlowUDPICMPRejectWindowLimit) {
		t.Fatalf("udpICMPSilent = %d, want %d", silent, totalFlows-packetFlowUDPICMPRejectWindowLimit)
	}

	rw.udpRejectMu.Lock()
	rw.udpRejectWindowStart = time.Now().Add(-packetFlowUDPICMPRejectWindow)
	rw.udpRejectMu.Unlock()
	injectUniqueUDPFlows(t, rw, 1000, 3)

	icmpCount = drainICMPResponses(t, rw)
	if icmpCount != 3 {
		t.Fatalf("next-window ICMP fallback responses = %d, want 3", icmpCount)
	}
	if rejected := atomic.LoadUint64(&rw.udpICMPRejected); rejected != uint64(packetFlowUDPICMPRejectWindowLimit+3) {
		t.Fatalf("udpICMPRejected after replenish = %d, want %d", rejected, packetFlowUDPICMPRejectWindowLimit+3)
	}
	if forwarded := atomic.LoadUint64(&rw.udpForwarded); forwarded != 0 {
		t.Fatalf("udpForwarded = %d, want 0", forwarded)
	}
}

func injectUniqueUDPFlows(t *testing.T, rw *packetFlowReadWriter, start, count int) {
	t.Helper()
	for i := start; i < start+count; i++ {
		packet := buildTestIPv4UDPPacket(
			[4]byte{10, 8, byte(i / 200), byte(i + 2)},
			[4]byte{93, 184, byte(i / 200), byte(34 + i)},
			uint16(30000+i),
			123,
			[]byte("ntp"),
		)
		if err := rw.Inject(packet); err != nil {
			t.Fatalf("Inject(%d) error = %v", i, err)
		}
	}
}

func drainICMPResponses(t *testing.T, rw *packetFlowReadWriter) int {
	t.Helper()
	icmpCount := 0
	for {
		select {
		case got := <-rw.outbound:
			if got[9] != 1 || got[20] != 3 || got[21] != 3 {
				t.Fatalf("response protocol/type/code = %d/%d/%d, want ICMP destination-port-unreachable", got[9], got[20], got[21])
			}
			icmpCount++
		default:
			return icmpCount
		}
	}
}

func waitMemoryTunWrite(t *testing.T, tun *memoryTun) []byte {
	t.Helper()
	select {
	case packet := <-tun.writes:
		return packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TUN write")
		return nil
	}
}

func buildTestIPv4UDPPacket(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(packet[12:16], packet[16:20], udp))
	return packet
}
