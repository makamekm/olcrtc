package server

import "testing"

func TestUDPDeniedPort(t *testing.T) {
	t.Setenv("OLCRTC_UDP_DENY_PORTS", "443, 8443")
	if !udpDeniedPort(443, false) || !udpDeniedPort(8443, false) || udpDeniedPort(53, false) {
		t.Fatal("wrong deny decision")
	}
	t.Setenv("OLCRTC_UDP_DENY_PORTS", "")
	if udpDeniedPort(443, false) {
		t.Fatal("denied without configuration")
	}
}

func TestUDPAllowedOnlyForRedirectedDNSOnJumper(t *testing.T) {
	t.Setenv("OLCRTC_UDP_DNS_ONLY", "1")
	t.Setenv("OLCRTC_UDP_DENY_PORTS", "")
	for _, port := range []int{53, 443, 3478} {
		if !udpDeniedPort(port, false) {
			t.Errorf("nonlocal UDP port %d was allowed", port)
		}
	}
	if udpDeniedPort(1053, true) {
		t.Fatal("redirected DNS to the local resolver was denied")
	}
}
