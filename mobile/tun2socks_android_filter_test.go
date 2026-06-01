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

func TestPacketFlowReadWriterForwardsNonDNSUDPToTun2Socks(t *testing.T) {
	resetMobileGlobals(t)
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)

	packet := buildTestIPv4UDPPacket([4]byte{10, 8, 0, 2}, [4]byte{93, 184, 216, 34}, 55555, 443, []byte("quic"))
	if err := rw.Inject(packet); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	select {
	case got := <-rw.inbound:
		if string(got) != string(packet) {
			t.Fatalf("forwarded packet mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for UDP packet to be forwarded")
	}
	if dropped := atomic.LoadUint64(&rw.udpDropped); dropped != 0 {
		t.Fatalf("udpDropped = %d, want 0", dropped)
	}
	if in := atomic.LoadUint64(&rw.inPackets); in != 1 {
		t.Fatalf("inPackets = %d, want 1", in)
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
