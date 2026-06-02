package client

import (
	"net"
	"testing"
)

func TestUDPRelaySessionTracksRecentClientAddrsNewestFirst(t *testing.T) {
	relay := &udpRelaySession{clientAddrs: map[string]*net.UDPAddr{}}
	addr1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}

	relay.UpdateClientAddr(addr1)
	relay.UpdateClientAddr(addr2)
	relay.UpdateClientAddr(addr1)

	if len(relay.clientOrder) != 2 {
		t.Fatalf("clientOrder len = %d, want 2", len(relay.clientOrder))
	}
	if relay.clientAddrs[addr1.String()].Port != addr1.Port || relay.clientAddrs[addr2.String()].Port != addr2.Port {
		t.Fatalf("tracked client addresses missing: %#v", relay.clientAddrs)
	}
}

func TestUDPRelaySessionCapsRecentClientAddrs(t *testing.T) {
	relay := &udpRelaySession{clientAddrs: map[string]*net.UDPAddr{}}
	for port := 10000; port < 10000+udpRelayMaxClientAddrs+3; port++ {
		relay.UpdateClientAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	}

	if len(relay.clientOrder) != udpRelayMaxClientAddrs {
		t.Fatalf("clientOrder len = %d, want %d", len(relay.clientOrder), udpRelayMaxClientAddrs)
	}
	if _, exists := relay.clientAddrs[(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}).String()]; exists {
		t.Fatal("oldest address was not evicted")
	}
	wantNewest := (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000 + udpRelayMaxClientAddrs + 2}).String()
	if relay.clientOrder[len(relay.clientOrder)-1] != wantNewest {
		t.Fatalf("newest tracked addr = %s, want %s", relay.clientOrder[len(relay.clientOrder)-1], wantNewest)
	}
}
