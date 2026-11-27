package server

import (
	"sync"
	"time"
)

const (
	directMinRetryDelay = 30 * time.Second
	directMaxRetryDelay = 2 * time.Minute
	directRetryHistory  = 5 * time.Minute
)

// Repeatedly attaching a measured-bad path interrupts a working backup.
// Increase the retry delay for repeated degradations while keeping automatic
// recovery available. An ordinary short-lived connection keeps its old delay.
type directRetryState struct {
	mu           sync.Mutex
	retryAt      time.Time
	lastDegraded time.Time
	delay        time.Duration
}

func (r *directRetryState) coolingDown(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return now.Before(r.retryAt)
}

func (r *directRetryState) recordClose(now time.Time, lifetime time.Duration, degraded bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delay := directMinRetryDelay
	if degraded {
		if now.Sub(r.lastDegraded) < directRetryHistory {
			delay = min(r.delay*2, directMaxRetryDelay)
		}
		r.lastDegraded, r.delay = now, delay
	} else if lifetime >= 20*time.Second {
		return
	}
	if next := now.Add(delay); next.After(r.retryAt) {
		r.retryAt = next
	}
}
