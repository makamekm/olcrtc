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
			lastIngress := p.lastIngressAt.Load()
			if carrierIngressStalled(now, lastIngress, p.lastPayloadSendAt.Load(), p.DirectPathActive()) {
				lastAttempt = now
				if requester.RequestReconnect() {
					logger.Infof("vp8channel: both paths stopped delivering ingress; rejoining conference")
				}
			}
		}
	}
}

func carrierIngressStalled(now time.Time, lastIngress, lastPayload int64, directActive bool) bool {
	return !directActive && lastIngress != 0 && lastPayload != 0 &&
		time.Duration(now.UnixNano()-lastIngress) >= ingressRecoveryDelay &&
		time.Duration(now.UnixNano()-lastPayload) <= recentPayloadWindow
}
