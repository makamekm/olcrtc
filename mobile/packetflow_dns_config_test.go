package mobile

import "testing"

func TestPacketFlowDNSUsesConfiguredServer(t *testing.T) {
	resetMobileGlobals(t)
	SetDNS("9.9.9.9:53")

	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	if rw.dnsServer != "9.9.9.9:53" {
		t.Fatalf("packetFlow dnsServer = %q, want configured DNS", rw.dnsServer)
	}
}

func TestPacketFlowDNSDefaultsToPublicResolver(t *testing.T) {
	resetMobileGlobals(t)

	rw := newPacketFlowReadWriter(1280, "127.0.0.1", 10808)
	if rw.dnsServer != defaultDNSServer {
		t.Fatalf("packetFlow dnsServer = %q, want %q", rw.dnsServer, defaultDNSServer)
	}
}
