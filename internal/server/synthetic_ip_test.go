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
