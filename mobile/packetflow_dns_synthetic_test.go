package mobile

import "testing"

func TestIsSyntheticDNSAnswer(t *testing.T) {
	answer := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x07, 'y', 'o', 'u', 't', 'u', 'b', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		198, 18, 0, 42,
	}
	if !isSyntheticDNSAnswer(answer) {
		t.Fatal("isSyntheticDNSAnswer() = false, want true")
	}
}

func TestIsSyntheticDNSAnswerAllowsPublicIPv4(t *testing.T) {
	answer := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		93, 184, 216, 34,
	}
	if isSyntheticDNSAnswer(answer) {
		t.Fatal("isSyntheticDNSAnswer() = true, want false")
	}
}

func TestSyntheticDNSAnswerAllowedOnlyForPrivateResolver(t *testing.T) {
	answer := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x07, 'y', 'o', 'u', 't', 'u', 'b', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		198, 18, 0, 42,
	}
	if !isUsableDNSAnswer(answer, nil, "192.168.50.53:53") {
		t.Fatal("synthetic answer from configured private resolver was rejected")
	}
	if isUsableDNSAnswer(answer, nil, "1.1.1.1:53") {
		t.Fatal("synthetic answer from public resolver was allowed")
	}
}

func TestIsPrivateDNSResolver(t *testing.T) {
	for _, resolver := range []string{"192.168.50.53:53", "10.0.0.1", "[fd00::1]:53"} {
		if !isPrivateDNSResolver(resolver) {
			t.Fatalf("isPrivateDNSResolver(%q) = false", resolver)
		}
	}
	for _, resolver := range []string{"1.1.1.1:53", "8.8.8.8", "dns.example"} {
		if isPrivateDNSResolver(resolver) {
			t.Fatalf("isPrivateDNSResolver(%q) = true", resolver)
		}
	}
}
