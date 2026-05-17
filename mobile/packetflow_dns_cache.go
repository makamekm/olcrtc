package mobile

import (
	"sync"
	"time"
)

const packetFlowDNSCacheTTL = 60 * time.Second

type packetFlowDNSCacheEntry struct {
	answer    []byte
	expiresAt time.Time
}

var packetFlowDNSCache = struct {
	mu      sync.Mutex
	entries map[string]packetFlowDNSCacheEntry
}{entries: make(map[string]packetFlowDNSCacheEntry)}

func getCachedDNSAnswer(query []byte) ([]byte, bool) {
	key, ok := packetFlowDNSCacheKey(query)
	if !ok {
		return nil, false
	}
	now := time.Now()
	packetFlowDNSCache.mu.Lock()
	defer packetFlowDNSCache.mu.Unlock()
	entry, ok := packetFlowDNSCache.entries[key]
	if !ok || now.After(entry.expiresAt) {
		delete(packetFlowDNSCache.entries, key)
		return nil, false
	}
	answer := append([]byte(nil), entry.answer...)
	if len(answer) >= 2 && len(query) >= 2 {
		answer[0] = query[0]
		answer[1] = query[1]
	}
	return answer, true
}

func putCachedDNSAnswer(query, answer []byte) {
	key, ok := packetFlowDNSCacheKey(query)
	if !ok || len(answer) == 0 {
		return
	}
	packetFlowDNSCache.mu.Lock()
	defer packetFlowDNSCache.mu.Unlock()
	if len(packetFlowDNSCache.entries) > 512 {
		packetFlowDNSCache.entries = make(map[string]packetFlowDNSCacheEntry)
	}
	packetFlowDNSCache.entries[key] = packetFlowDNSCacheEntry{
		answer:    append([]byte(nil), answer...),
		expiresAt: time.Now().Add(packetFlowDNSCacheTTL),
	}
}

func packetFlowDNSCacheKey(query []byte) (string, bool) {
	if len(query) < 12 {
		return "", false
	}
	return string(query[2:]), true
}
