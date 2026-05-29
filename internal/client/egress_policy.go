package client

import (
	"net"
	"os"
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
		ip[0] == 0 ||
		ip[0] == 10 ||
		ip[0] == 127 ||
		(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) ||
		(ip[0] == 169 && ip[1] == 254) ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] >= 224)
}

func isBlockedEgressHostname(addr string) bool {
	host := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(addr, ".")))
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan")
}

func allowBlockedEgressTargets() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("OLCRTC_ALLOW_BLOCKED_EGRESS")))
	return value == "1" || value == "true" || value == "yes"
}

func isBlockedEgressTarget(addr string) bool {
	return isBlockedEgressIPv4Address(addr) || isBlockedEgressHostname(addr)
}
