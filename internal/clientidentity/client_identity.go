// Package clientidentity normalizes logical client IDs shared by server and transports.
package clientidentity

import "strings"

// Normalize removes runtime-only transport decorations while preserving the stable logical client ID.
func Normalize(clientID string) string {
	identity := strings.TrimPrefix(clientID, "srv-")
	if separator := strings.LastIndexByte(identity, '@'); separator > 0 {
		generation := identity[separator+1:]
		if len(generation) >= 10 && strings.IndexFunc(generation, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
			identity = identity[:separator]
		}
	}
	return identity
}
