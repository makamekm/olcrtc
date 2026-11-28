package vp8channel

import (
	"context"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/carrier"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

const (
	ingressRecoveryDelay    = 12 * time.Second
	ingressRecoveryCooldown = 45 * time.Second
	recentPayloadWindow     = 45 * time.Second
)

// A connected carrier can stop delivering even its peer's idle frames.
// Rejoin after active traffic loses both paths, using the carrier's existing
// lifecycle loop so the host VPN interface stays attached.
func (p *streamTransport) watchCarrierIngress(ctx context.Context, requester carrier.ReconnectRequester) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var lastAttempt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.closeCh:
			return
		case now := <-tick.C:
			if now.Sub(lastAttempt) < ingressRecoveryCooldown {
				continue
			}
			blockedSince := p.carrierBlockedSince.Load()
			if blockedSince != 0 && p.sendPathReady() {
				p.carrierBlockedSince.CompareAndSwap(blockedSince, 0)
				blockedSince = 0
			}
			writeBlocked := blockedSince != 0 && now.Sub(time.Unix(0, blockedSince)) >= ingressRecoveryDelay
			ingressStalled := carrierIngressStalled(now, p.lastIngressAt.Load(), p.lastPayloadSendAt.Load(), p.DirectPathActive())
			if !writeBlocked && !ingressStalled {
				continue
			}
			lastAttempt = now
			if requester.RequestReconnect() {
				logger.Infof("vp8channel: rejoining conference (send blocked=%t, ingress stalled=%t)", writeBlocked, ingressStalled)
			}
		}
	}
}

func carrierIngressStalled(now time.Time, lastIngress, lastPayload int64, directActive bool) bool {
	return !directActive && lastIngress != 0 && lastPayload != 0 &&
		time.Duration(now.UnixNano()-lastIngress) >= ingressRecoveryDelay &&
		time.Duration(now.UnixNano()-lastPayload) <= recentPayloadWindow
}
