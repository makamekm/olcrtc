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

func TestAndroidTunReadWriterNormalizesTCPBeforeTunWrite(t *testing.T) {
	resetMobileGlobals(t)
	tun := newMemoryTun()
	rw := newAndroidTunReadWriter(tun, 1280, "127.0.0.1", 10808)

	packet := buildTestIPv4TCPSynPacket([4]byte{93, 184, 216, 34}, [4]byte{10, 8, 0, 2}, 443, 55555, 1200)
	packet[10], packet[11] = 0x12, 0x34
	ihl := int(packet[0]&0x0f) * 4
	packet[ihl+16], packet[ihl+17] = 0x56, 0x78
	if _, err := rw.Write(packet); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := waitMemoryTunWrite(t, tun)
	if got[10] == 0x12 && got[11] == 0x34 {
		t.Fatalf("IPv4 checksum was not normalized")
	}
	if got[ihl+16] == 0x56 && got[ihl+17] == 0x78 {
		t.Fatalf("TCP checksum was not normalized")
	}
	if out := atomic.LoadUint64(&rw.outPackets); out != 1 {
		t.Fatalf("outPackets = %d, want 1", out)
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
	got := drainSingleICMPResponse(t, rw)
	if [4]byte(got[12:16]) != [4]byte{93, 184, 216, 34} || [4]byte(got[16:20]) != [4]byte{10, 8, 0, 2} {
		t.Fatalf("ICMP response src/dst = %v/%v, want original dst/src", got[12:16], got[16:20])
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != 1 {
		t.Fatalf("udpDropped = %d, want 1", dropped)
	}
	if rejected := atomic.LoadUint64(&rw.udpICMPRejected); rejected != 1 {
		t.Fatalf("udpICMPRejected = %d, want 1", rejected)
	}
	if silent := atomic.LoadUint64(&rw.udpICMPSilent); silent != 0 {
		t.Fatalf("udpICMPSilent = %d, want 0", silent)
	}
	if forwarded := atomic.LoadUint64(&rw.udpForwarded); forwarded != 0 {
		t.Fatalf("udpForwarded = %d, want 0", forwarded)
	}
	if in := atomic.LoadUint64(&rw.inPackets); in != 0 {
		t.Fatalf("inPackets = %d, want 0", in)
	}
}

func TestPacketFlowReadWriterRejectsRepeatedNonDNSUDP(t *testing.T) {
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
	if got := drainICMPResponses(t, rw); got != 2 {
		t.Fatalf("ICMP responses = %d, want 2", got)
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != 2 {
		t.Fatalf("udpDropped = %d, want 2", dropped)
	}
	if rejected := atomic.LoadUint64(&rw.udpICMPRejected); rejected != 2 {
		t.Fatalf("udpICMPRejected = %d, want 2", rejected)
	}
	if silent := atomic.LoadUint64(&rw.udpICMPSilent); silent != 0 {
		t.Fatalf("udpICMPSilent = %d, want 0", silent)
	}
	if in := atomic.LoadUint64(&rw.inPackets); in != 0 {
		t.Fatalf("inPackets = %d, want 0", in)
	}
}

func TestPacketFlowReadWriterRateLimitsICMPFallback(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	totalFlows := packetFlowUDPICMPRejectWindowLimit + 4

	injectUniqueUDPFlows(t, rw, 0, totalFlows)

	if got := drainICMPResponses(t, rw); got != packetFlowUDPICMPRejectWindowLimit {
		t.Fatalf("ICMP responses = %d, want %d", got, packetFlowUDPICMPRejectWindowLimit)
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != uint64(totalFlows) {
		t.Fatalf("udpDropped = %d, want %d", dropped, totalFlows)
	}
	if rejected := atomic.LoadUint64(&rw.udpICMPRejected); rejected != uint64(packetFlowUDPICMPRejectWindowLimit) {
		t.Fatalf("udpICMPRejected = %d, want %d", rejected, packetFlowUDPICMPRejectWindowLimit)
	}
	if silent := atomic.LoadUint64(&rw.udpICMPSilent); silent != 4 {
		t.Fatalf("udpICMPSilent = %d, want 4", silent)
	}

	rw.udpRejectMu.Lock()
	rw.udpRejectWindowStart = time.Now().Add(-packetFlowUDPICMPRejectWindow)
	rw.udpRejectMu.Unlock()
	injectUniqueUDPFlows(t, rw, 1000, 3)

	if got := drainICMPResponses(t, rw); got != 3 {
		t.Fatalf("ICMP responses after replenish = %d, want 3", got)
	}
	if rejected := atomic.LoadUint64(&rw.udpICMPRejected); rejected != uint64(packetFlowUDPICMPRejectWindowLimit+3) {
		t.Fatalf("udpICMPRejected after replenish = %d, want %d", rejected, packetFlowUDPICMPRejectWindowLimit+3)
	}
	if silent := atomic.LoadUint64(&rw.udpICMPSilent); silent != 4 {
		t.Fatalf("udpICMPSilent after replenish = %d, want 4", silent)
	}
	if forwarded := atomic.LoadUint64(&rw.udpForwarded); forwarded != 0 {
		t.Fatalf("udpForwarded = %d, want 0", forwarded)
	}
}

func TestPacketFlowReadWriterSkipsInvalidPacketsWithoutZeroNilRead(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(64, "127.0.0.1", 10808)
	valid := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 8, 0, 2, 93, 184, 216, 34}

	rw.inbound <- nil
	rw.inbound <- make([]byte, 65)
	rw.inbound <- valid

	buf := make([]byte, 128)
	n, err := rw.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != len(valid) || string(buf[:n]) != string(valid) {
		t.Fatalf("Read() returned len=%d bytes=%v, want valid packet", n, buf[:n])
	}
	if zero := atomic.LoadUint64(&rw.zeroReadSkipped); zero != 1 {
		t.Fatalf("zeroReadSkipped = %d, want 1", zero)
	}
	if oversize := atomic.LoadUint64(&rw.oversizeReadSkipped); oversize != 1 {
		t.Fatalf("oversizeReadSkipped = %d, want 1", oversize)
	}
}

func TestPacketFlowReadWriterClampsTCPMSSBeforeTun2Socks(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	packet := buildTestIPv4TCPSynPacket([4]byte{10, 8, 0, 2}, [4]byte{93, 184, 216, 34}, 55555, 443, 1460)

	if err := rw.Inject(packet); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}
	select {
	case got := <-rw.inbound:
		if mss := tcpMSSOption(t, got); mss != 1200 {
			t.Fatalf("clamped MSS = %d, want 1200", mss)
		}
	case <-time.After(time.Second):
		t.Fatal("missing forwarded TCP SYN")
	}
	if clamped := atomic.LoadUint64(&rw.tcpMSSClamped); clamped != 1 {
		t.Fatalf("tcpMSSClamped = %d, want 1", clamped)
	}
	if fixed := atomic.LoadUint64(&rw.tcpChecksumFixed); fixed != 1 {
		t.Fatalf("tcpChecksumFixed = %d, want 1", fixed)
	}
}

func TestPacketFlowReadWriterNormalizesOutboundTCP(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	packet := buildTestIPv4TCPSynPacket([4]byte{93, 184, 216, 34}, [4]byte{10, 8, 0, 2}, 443, 55555, 1200)
	packet[10], packet[11] = 0x12, 0x34
	packet[20+16], packet[20+17] = 0x56, 0x78

	if _, err := rw.Write(packet); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := <-rw.outbound
	if binary.BigEndian.Uint16(got[10:12]) == 0x1234 {
		t.Fatal("IPv4 checksum was not normalized")
	}
	if binary.BigEndian.Uint16(got[36:38]) == 0x5678 {
		t.Fatal("TCP checksum was not normalized")
	}
	if tcpOut := atomic.LoadUint64(&rw.tcpOutbound); tcpOut != 1 {
		t.Fatalf("tcpOutbound = %d, want 1", tcpOut)
	}
	if fixed := atomic.LoadUint64(&rw.tcpOutboundCsumFixed); fixed != 1 {
		t.Fatalf("tcpOutboundCsumFixed = %d, want 1", fixed)
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

func drainSingleICMPResponse(t *testing.T, rw *packetFlowReadWriter) []byte {
	t.Helper()
	select {
	case got := <-rw.outbound:
		if got[9] != 1 || got[20] != 3 || got[21] != 3 {
			t.Fatalf("response protocol/type/code = %d/%d/%d, want ICMP destination-port-unreachable", got[9], got[20], got[21])
		}
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICMP response")
		return nil
	}
}

func assertPacketFlowOutboundEmpty(t *testing.T, rw *packetFlowReadWriter) {
	t.Helper()
	select {
	case got := <-rw.outbound:
		t.Fatalf("unexpected packetFlow outbound packet len=%d proto=%d", len(got), got[9])
	default:
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

func buildTestIPv4TCPSynPacket(src, dst [4]byte, srcPort, dstPort uint16, mss uint16) []byte {
	tcpHeaderLen := 24
	totalLen := 20 + tcpHeaderLen
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = byte(tcpHeaderLen/4) << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	normalizeIPv4Checksums(packet)
	return packet
}

func tcpMSSOption(t *testing.T, packet []byte) uint16 {
	t.Helper()
	ihl := int(packet[0]&0x0f) * 4
	tcp := packet[ihl:]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	for i := 20; i < tcpHeaderLen; {
		kind := tcp[i]
		switch kind {
		case 0:
			break
		case 1:
			i++
			continue
		}
		if i+1 >= tcpHeaderLen {
			break
		}
		optLen := int(tcp[i+1])
		if optLen < 2 || i+optLen > tcpHeaderLen {
			break
		}
		if kind == 2 && optLen == 4 {
			return binary.BigEndian.Uint16(tcp[i+2 : i+4])
		}
		i += optLen
	}
	t.Fatal("missing TCP MSS option")
	return 0
}
