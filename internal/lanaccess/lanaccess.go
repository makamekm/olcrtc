// Package lanaccess holds the private subnets a deployment explicitly
// exposes through the tunnel, so remote clients can reach the server's
// local network (e.g. http://192.168.0.209:8080) as if they were on it.
// Everything else in private ranges stays blocked on both ends.
package lanaccess

import (
	"net"
	"os"
	"strings"
	"sync"
)

// EnvName lists the exposed subnets as comma-separated CIDRs.
const EnvName = "OLCRTC_LAN_SUBNETS"

var (
	mu      sync.RWMutex
	subnets []*net.IPNet
	loaded  bool
)

// Set replaces the exposed subnets ("" disables LAN access).
func Set(spec string) {
	mu.Lock()
	defer mu.Unlock()
	subnets = Parse(spec)
	loaded = true
}

// Parse turns "192.168.0.0/24, 10.1.0.0/16" into networks, skipping junk.
// Only IPv4 private ranges are accepted.
func Parse(spec string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			part += "/32"
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil || network.IP.To4() == nil || !isPrivateIPv4(network.IP) {
			continue
		}
		out = append(out, network)
	}
	return out
}

func current() []*net.IPNet {
	mu.RLock()
	if loaded {
		defer mu.RUnlock()
		return subnets
	}
	mu.RUnlock()
	Set(os.Getenv(EnvName))
	mu.RLock()
	defer mu.RUnlock()
	return subnets
}

// Contains reports whether addr (an IP literal) is inside an exposed subnet.
func Contains(addr string) bool {
	ip := net.ParseIP(strings.Trim(addr, "[]")).To4()
	if ip == nil {
		return false
	}
	for _, network := range current() {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && (ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168))
}
