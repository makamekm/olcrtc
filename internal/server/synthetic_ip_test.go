package server

import "testing"

func TestIsSyntheticIPv4Address(t *testing.T) {
	for _, addr := range []string{"198.18.0.1", "198.19.255.254"} {
		if !isSyntheticIPv4Address(addr) {
			t.Fatalf("isSyntheticIPv4Address(%q) = false", addr)
		}
	}
}

func TestIsSyntheticIPv4AddressAllowsPublic(t *testing.T) {
	for _, addr := range []string{"142.251.13.136", "1.1.1.1", "example.com", ""} {
		if isSyntheticIPv4Address(addr) {
			t.Fatalf("isSyntheticIPv4Address(%q) = true", addr)
		}
	}
}

func TestIsBlockedEgressIPv4Address(t *testing.T) {
	for _, addr := range []string{
		"10.0.0.1",
		"169.254.1.1",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.0.209",
		"198.18.0.1",
	} {
		if !isBlockedEgressIPv4Address(addr) {
			t.Fatalf("isBlockedEgressIPv4Address(%q) = false", addr)
		}
	}
}

func TestIsBlockedEgressIPv4AddressAllowsPublicAndHosts(t *testing.T) {
	for _, addr := range []string{"142.251.13.136", "1.1.1.1", "8.8.8.8", "example.com", ""} {
		if isBlockedEgressIPv4Address(addr) {
			t.Fatalf("isBlockedEgressIPv4Address(%q) = true", addr)
		}
	}
}
