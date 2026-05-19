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

type packetFlowDNSInflightEntry struct {
	done   chan struct{}
	answer []byte
	err    error
}

var packetFlowDNSCache = struct {
	mu      sync.Mutex
	entries map[string]packetFlowDNSCacheEntry
}{entries: make(map[string]packetFlowDNSCacheEntry)}

var packetFlowDNSInflight = struct {
	mu      sync.Mutex
	entries map[string]*packetFlowDNSInflightEntry
}{entries: make(map[string]*packetFlowDNSInflightEntry)}

func clearPacketFlowDNSCache() {
	packetFlowDNSCache.mu.Lock()
	packetFlowDNSCache.entries = make(map[string]packetFlowDNSCacheEntry)
	packetFlowDNSCache.mu.Unlock()

	packetFlowDNSInflight.mu.Lock()
	packetFlowDNSInflight.entries = make(map[string]*packetFlowDNSInflightEntry)
	packetFlowDNSInflight.mu.Unlock()
}

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

func resolveDNSWithInflight(query []byte, resolve func() ([]byte, error)) ([]byte, error) {
	key, ok := packetFlowDNSCacheKey(query)
	if !ok {
		return resolve()
	}

	packetFlowDNSInflight.mu.Lock()
	if entry, exists := packetFlowDNSInflight.entries[key]; exists {
		packetFlowDNSInflight.mu.Unlock()
		<-entry.done
		answer := append([]byte(nil), entry.answer...)
		if len(answer) >= 2 && len(query) >= 2 {
			answer[0] = query[0]
			answer[1] = query[1]
		}
		return answer, entry.err
	}
	entry := &packetFlowDNSInflightEntry{done: make(chan struct{})}
	packetFlowDNSInflight.entries[key] = entry
	packetFlowDNSInflight.mu.Unlock()

	answer, err := resolve()
	entry.answer = append([]byte(nil), answer...)
	entry.err = err
	close(entry.done)

	packetFlowDNSInflight.mu.Lock()
	delete(packetFlowDNSInflight.entries, key)
	packetFlowDNSInflight.mu.Unlock()

	if len(answer) >= 2 && len(query) >= 2 {
		answer = append([]byte(nil), answer...)
		answer[0] = query[0]
		answer[1] = query[1]
	}
	return answer, err
}

func packetFlowDNSCacheKey(query []byte) (string, bool) {
	if len(query) < 12 {
		return "", false
	}
	return string(query[2:]), true
}
