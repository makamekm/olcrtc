package mobile

import (
	"strings"
	"testing"
	"time"
)

func TestPacketFlowDNSDirectTimeoutsStayShortForYouTubeNavigation(t *testing.T) {
	if packetFlowDNSDirectTimeout > 400*time.Millisecond {
		t.Fatalf("packetFlowDNSDirectTimeout = %s, want <= 400ms", packetFlowDNSDirectTimeout)
	}
	if packetFlowDNSSocksTimeout > 2*time.Second {
		t.Fatalf("packetFlowDNSSocksTimeout = %s, want <= 2s", packetFlowDNSSocksTimeout)
	}
}

func TestPacketFlowDNSDebugStatsExposeResolverPath(t *testing.T) {
	clearPacketFlowDNSCache()
	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	rw.countDNSAnswerSource(packetFlowDNSAnswerDirectUDP)
	rw.countDNSAnswerSource(packetFlowDNSAnswerDirectTCP)
	rw.countDNSAnswerSource(packetFlowDNSAnswerSocks)
	rw.countDNSAnswerSource(packetFlowDNSAnswerCache)
	packetFlowTun2Socks.mu.Lock()
	old := packetFlowTun2Socks.rw
	packetFlowTun2Socks.rw = rw
	packetFlowTun2Socks.mu.Unlock()
	t.Cleanup(func() {
		packetFlowTun2Socks.mu.Lock()
		packetFlowTun2Socks.rw = old
		packetFlowTun2Socks.mu.Unlock()
	})

	stats := MobilePacketFlowDebugStats()
	for _, want := range []string{
		"dns_direct_udp=1",
		"dns_direct_tcp=1",
		"dns_socks=1",
		"dns_cache=1",
	} {
		if !strings.Contains(stats, want) {
			t.Fatalf("stats missing %q: %s", want, stats)
		}
	}
}
