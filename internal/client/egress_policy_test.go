package client

import "testing"

func TestIsBlockedEgressIPv4Address(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0",
		"10.0.0.1",
		"100.64.0.1",
		"100.127.255.254",
		"127.0.0.1",
		"169.254.1.1",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.0.1",
		"198.18.0.1",
		"198.19.255.254",
		"224.0.0.1",
	} {
		if !isBlockedEgressIPv4Address(addr) {
			t.Fatalf("isBlockedEgressIPv4Address(%q) = false", addr)
		}
	}
	for _, addr := range []string{"1.1.1.1", "8.8.8.8", "connectivitycheck.gstatic.com", ""} {
		if isBlockedEgressIPv4Address(addr) {
			t.Fatalf("isBlockedEgressIPv4Address(%q) = true", addr)
		}
	}
}

func TestIsBlockedEgressHostname(t *testing.T) {
	for _, addr := range []string{"localhost", "printer.local", "router.lan", "api.localhost."} {
		if !isBlockedEgressHostname(addr) {
			t.Fatalf("isBlockedEgressHostname(%q) = false", addr)
		}
	}
	for _, addr := range []string{"example.com", "connectivitycheck.gstatic.com", ""} {
		if isBlockedEgressHostname(addr) {
			t.Fatalf("isBlockedEgressHostname(%q) = true", addr)
		}
	}
}

func TestShouldServeConnectivityProbeLocally(t *testing.T) {
	if !shouldServeConnectivityProbeLocally("connectivitycheck.gstatic.com", 80) {
		t.Fatal("connectivitycheck.gstatic.com:80 was not recognized")
	}
	if shouldServeConnectivityProbeLocally("connectivitycheck.gstatic.com", 443) {
		t.Fatal("connectivitycheck.gstatic.com:443 was incorrectly recognized")
	}
	if shouldServeConnectivityProbeLocally("example.com", 80) {
		t.Fatal("example.com:80 was incorrectly recognized")
	}
}
