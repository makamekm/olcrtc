package lanaccess

import "testing"

func TestContainsOnlyConfiguredPrivateSubnets(t *testing.T) {
	Set("192.168.0.0/24, 8.8.8.0/24, junk, 10.20.0.5")
	t.Cleanup(func() { Set("") })
	cases := map[string]bool{
		"192.168.0.209": true,
		"192.168.1.1":   false,
		"8.8.8.8":       false, // public ranges are never "LAN"
		"10.20.0.5":     true,
		"10.20.0.6":     false,
		"example.com":   false,
	}
	for addr, want := range cases {
		if got := Contains(addr); got != want {
			t.Fatalf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestEmptySpecDisablesLANAccess(t *testing.T) {
	Set("")
	if Contains("192.168.0.209") {
		t.Fatal("LAN access must be off without configured subnets")
	}
}
