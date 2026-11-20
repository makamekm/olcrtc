package directpath

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

// publicIPStunServers answer from networks where foreign STUN is filtered.
var publicIPStunServers = []string{"stun.rtc.yandex.net:3478", "stun.l.google.com:19302"} //nolint:gochecknoglobals // static config

// interfacePublicIPv4 returns a global unicast, non-private IPv4 bound to a
// local interface (typical cloud VM or a host with a public address), or "".
func interfacePublicIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || isSharedOrSynthetic(ip) {
			continue
		}
		return ip.String()
	}
	return ""
}

func isSharedOrSynthetic(ip net.IP) bool {
	return (ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) || // carrier-grade NAT
		(ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) // benchmark / fake-IP ranges
}

// stunPublicIPv4 asks STUN servers for this host's public IPv4 (clouds with
// 1:1 NAT, Docker with published ports).
func stunPublicIPv4() (string, error) {
	var lastErr error
	for _, server := range publicIPStunServers {
		ip, err := stunMappedIPv4(server)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func stunMappedIPv4(server string) (string, error) {
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", server, err)
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteToUDP(msg.Raw, raddr); err != nil {
		return "", fmt.Errorf("stun write: %w", err)
	}
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", fmt.Errorf("stun %s: %w", server, err)
	}
	resp := &stun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return "", fmt.Errorf("stun decode: %w", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		return "", fmt.Errorf("stun mapped address: %w", err)
	}
	ip := xor.IP.To4()
	if ip == nil || ip.IsPrivate() || isSharedOrSynthetic(ip) {
		return "", fmt.Errorf("stun %s returned non-public %s", server, xor.IP)
	}
	return ip.String(), nil
}
