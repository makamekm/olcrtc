package server

import "testing"

func TestUDPDeniedPort(t *testing.T) {
	t.Setenv("OLCRTC_UDP_DENY_PORTS", "443, 8443")
	if !udpDeniedPort(443) || !udpDeniedPort(8443) || udpDeniedPort(53) {
		t.Fatal("wrong deny decision")
	}
	t.Setenv("OLCRTC_UDP_DENY_PORTS", "")
	if udpDeniedPort(443) {
		t.Fatal("denied without configuration")
	}
}
