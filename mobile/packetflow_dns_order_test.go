package mobile

import (
	"errors"
	"testing"
	"time"
)

func TestPacketFlowDNSPrefersDirectUDPBeforeCarrierSocks(t *testing.T) {
	clearPacketFlowDNSCache()
	t.Cleanup(clearPacketFlowDNSCache)
	oldUDP := packetFlowDNSResolveUDPDirect
	oldTCP := packetFlowDNSResolveTCPDirect
	oldSocks := packetFlowDNSResolveTCPSocks
	t.Cleanup(func() {
		packetFlowDNSResolveUDPDirect = oldUDP
		packetFlowDNSResolveTCPDirect = oldTCP
		packetFlowDNSResolveTCPSocks = oldSocks
	})

	query := dnsPayloadFromQueryPacket(dnsQueryPacket("rr1---sn-n8v7knl6.googlevideo.com", 1), t)
	udpAnswer := dnsAnswerPayload(query)
	calls := []string{}

	packetFlowDNSResolveUDPDirect = func(got []byte, dnsServer string) ([]byte, error) {
		calls = append(calls, "udp")
		if dnsServer != "9.9.9.9:53" {
			t.Fatalf("dnsServer = %q, want configured resolver", dnsServer)
		}
		return udpAnswer, nil
	}
	packetFlowDNSResolveTCPDirect = func([]byte, string) ([]byte, error) {
		calls = append(calls, "tcp")
		return nil, errors.New("tcp should not run after usable udp answer")
	}
	packetFlowDNSResolveTCPSocks = func([]byte, string, int, string) ([]byte, error) {
		calls = append(calls, "socks")
		return nil, errors.New("socks should not run after usable udp answer")
	}

	answer, _, err := resolveDNSOverTCPViaSocks(query, "127.0.0.1", 10808, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("resolveDNSOverTCPViaSocks error = %v", err)
	}
	if string(answer) != string(udpAnswer) {
		t.Fatalf("answer mismatch")
	}
	if got, want := calls, []string{"udp"}; stringSliceJoin(got) != stringSliceJoin(want) {
		t.Fatalf("resolver calls = %v, want %v", got, want)
	}
}

func TestPacketFlowDNSFallsBackToSocksAfterDirectFailures(t *testing.T) {
	clearPacketFlowDNSCache()
	t.Cleanup(clearPacketFlowDNSCache)
	oldUDP := packetFlowDNSResolveUDPDirect
	oldTCP := packetFlowDNSResolveTCPDirect
	oldSocks := packetFlowDNSResolveTCPSocks
	t.Cleanup(func() {
		packetFlowDNSResolveUDPDirect = oldUDP
		packetFlowDNSResolveTCPDirect = oldTCP
		packetFlowDNSResolveTCPSocks = oldSocks
	})

	query := dnsPayloadFromQueryPacket(dnsQueryPacket("rr2---sn-n8v7knl6.googlevideo.com", 1), t)
	socksAnswer := dnsAnswerPayload(query)
	calls := []string{}

	packetFlowDNSResolveUDPDirect = func([]byte, string) ([]byte, error) {
		calls = append(calls, "udp")
		return nil, errors.New("udp blocked")
	}
	packetFlowDNSResolveTCPDirect = func([]byte, string) ([]byte, error) {
		calls = append(calls, "tcp")
		return nil, errors.New("tcp blocked")
	}
	packetFlowDNSResolveTCPSocks = func([]byte, string, int, string) ([]byte, error) {
		calls = append(calls, "socks")
		return socksAnswer, nil
	}

	answer, _, err := resolveDNSOverTCPViaSocks(query, "127.0.0.1", 10808, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("resolveDNSOverTCPViaSocks error = %v", err)
	}
	if string(answer) != string(socksAnswer) {
		t.Fatalf("answer mismatch")
	}
	if got, want := calls, []string{"udp", "tcp", "socks"}; stringSliceJoin(got) != stringSliceJoin(want) {
		t.Fatalf("resolver calls = %v, want %v", got, want)
	}
}

func dnsPayloadFromQueryPacket(packet []byte, t *testing.T) []byte {
	t.Helper()
	payload, ok := dnsPayloadFromIPv4UDP(packet)
	if !ok {
		t.Fatalf("dnsPayloadFromIPv4UDP failed")
	}
	return payload
}

func dnsAnswerPayload(query []byte) []byte {
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	answer[3] = (answer[3] & 0xf0) | 0x00
	return answer
}

func stringSliceJoin(values []string) string {
	out := ""
	for _, value := range values {
		out += value + "\x00"
	}
	return out
}

func TestPacketFlowDNSHedgesToSocksWhenDirectResolverHangs(t *testing.T) {
	clearPacketFlowDNSCache()
	t.Cleanup(clearPacketFlowDNSCache)
	oldUDP := packetFlowDNSResolveUDPDirect
	oldTCP := packetFlowDNSResolveTCPDirect
	oldSocks := packetFlowDNSResolveTCPSocks
	t.Cleanup(func() {
		packetFlowDNSResolveUDPDirect = oldUDP
		packetFlowDNSResolveTCPDirect = oldTCP
		packetFlowDNSResolveTCPSocks = oldSocks
	})

	query := dnsPayloadFromQueryPacket(dnsQueryPacket("rr3---sn-n8v7knl6.googlevideo.com", 1), t)
	socksAnswer := dnsAnswerPayload(query)
	// A private LAN resolver seen from LTE: direct attempts just time out.
	packetFlowDNSResolveUDPDirect = func([]byte, string) ([]byte, error) {
		time.Sleep(packetFlowDNSDirectTimeout)
		return nil, errors.New("udp timeout")
	}
	packetFlowDNSResolveTCPDirect = func([]byte, string) ([]byte, error) {
		time.Sleep(packetFlowDNSDirectTimeout)
		return nil, errors.New("tcp timeout")
	}
	packetFlowDNSResolveTCPSocks = func([]byte, string, int, string) ([]byte, error) {
		return socksAnswer, nil
	}

	start := time.Now()
	answer, source, err := resolveDNSOverTCPViaSocks(query, "127.0.0.1", 10808, "192.168.0.191:53")
	if err != nil {
		t.Fatalf("resolveDNSOverTCPViaSocks error = %v", err)
	}
	if string(answer) != string(socksAnswer) || source != packetFlowDNSAnswerSocks {
		t.Fatalf("expected the SOCKS answer, got source=%v", source)
	}
	if elapsed := time.Since(start); elapsed >= packetFlowDNSDirectTimeout {
		t.Fatalf("hedged lookup took %v; must not wait for the direct timeouts", elapsed)
	}
}
