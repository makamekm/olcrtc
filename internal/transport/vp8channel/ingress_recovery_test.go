package vp8channel

import (
	"context"
	"testing"
	"time"
)

func TestCarrierIngressRecoveryRequiresTrafficAndLossOfBothPaths(t *testing.T) {
	now := time.Unix(100, 0)
	old := now.Add(-13 * time.Second).UnixNano()
	fresh := now.Add(-time.Second).UnixNano()
	idle := now.Add(-50 * time.Second).UnixNano()
	for _, tc := range []struct {
		name             string
		ingress, payload int64
		direct, want     bool
	}{
		{"active session with both paths silent", old, fresh, false, true},
		{"conference delivering keepalives", fresh, fresh, false, false},
		{"direct still active", old, fresh, true, false},
		{"session with no established peer", 0, fresh, false, false},
		{"session idle", idle, idle, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := carrierIngressStalled(now, tc.ingress, tc.payload, tc.direct); got != tc.want {
				t.Fatalf("stalled = %v, want %v", got, tc.want)
			}
		})
	}
}

type recordedReconnect chan struct{}

func (r recordedReconnect) RequestReconnect() bool {
	select {
	case r <- struct{}{}:
		return true
	default:
		return false
	}
}

func TestWatchCarrierIngressRequestsRejoinWhenFramesStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &streamTransport{closeCh: make(chan struct{})}
	now := time.Now()
	p.lastIngressAt.Store(now.Add(-ingressRecoveryDelay).UnixNano())
	p.lastPayloadSendAt.Store(now.UnixNano())
	requested := make(recordedReconnect, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		p.watchCarrierIngress(ctx, requested)
	}()
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("carrier recovery was not requested")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("ingress watcher did not stop")
	}
}

func TestWatchCarrierIngressRejoinsWhenWritesCannotReachKCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &streamTransport{
		stream:   &fakeVideoStream{},
		closeCh:  make(chan struct{}),
		outbound: make(chan []byte, 8),
		kcp:      &kcpRuntime{},
	}
	if p.CanSend() || p.carrierBlockedSince.Load() == 0 {
		t.Fatal("unavailable send paths did not record blocked writer")
	}
	p.carrierBlockedSince.Store(time.Now().Add(-ingressRecoveryDelay).UnixNano())
	// Receiving idle frames cannot make a blocked outbound path writable.
	p.lastIngressAt.Store(time.Now().UnixNano())
	requested := make(recordedReconnect, 1)
	go p.watchCarrierIngress(ctx, requested)
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked writer did not request an in-process media rejoin")
	}
}

func TestCanSendClearsCarrierBlockWhenPublisherReturns(t *testing.T) {
	stream := &fakeVideoStream{}
	p := &streamTransport{
		stream:   stream,
		outbound: make(chan []byte, 8),
		kcp:      &kcpRuntime{},
	}
	if p.CanSend() || p.carrierBlockedSince.Load() == 0 {
		t.Fatal("unavailable send paths did not record blocked writer")
	}
	stream.canSend = true
	if !p.CanSend() || p.carrierBlockedSince.Load() != 0 {
		t.Fatal("a healthy carrier did not clear the write block")
	}
}
