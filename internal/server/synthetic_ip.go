package server

import "net"

func isSyntheticIPv4Address(addr string) bool {
	ip := net.ParseIP(addr).To4()
	return ip != nil && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}
