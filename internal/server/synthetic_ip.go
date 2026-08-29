package server

import (
	"net"
	"strconv"
	"strings"
)

func isSyntheticIPv4Address(addr string) bool {
	ip := net.ParseIP(addr).To4()
	return ip != nil && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

func isBlockedEgressIPv4Address(addr string) bool {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return false
	}
	return isSyntheticIPv4Address(addr) ||
		ip[0] == 10 ||
		(ip[0] == 169 && ip[1] == 254) ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

func isConfiguredDNSTarget(dnsServer, targetAddr string, targetPort int) bool {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(dnsServer))
	if err != nil {
		host = strings.TrimSpace(dnsServer)
		portText = "53"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != targetPort {
		return false
	}
	wantIP := net.ParseIP(strings.Trim(host, "[]"))
	gotIP := net.ParseIP(strings.Trim(targetAddr, "[]"))
	if wantIP != nil && gotIP != nil {
		return wantIP.Equal(gotIP)
	}
	return strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(targetAddr, "."))
}
