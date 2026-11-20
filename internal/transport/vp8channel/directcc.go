package vp8channel

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/directpath"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	kcp "github.com/xtaci/kcp-go/v5"
)

// Delay-based send control for the direct path.
//
// KCP runs without congestion control, so over the direct path it kept a
// full send window (384 segments, ~375 KB) in flight. On a fast path that
// window is many times the bandwidth-delay product: it piled up as a
// 100-300 ms queue in the network and in the data channel, the RTT swung
// with it and KCP's retransmission timer fired for segments that were only
// queued - about 30% of everything sent arrived twice.
//
// While a direct path carries the tunnel, directCC keeps the send window
// near the path's bandwidth-delay product (Vegas style: shrink when the
// smoothed RTT rises more than a small queueing allowance above the path's
// minimum RTT, grow while the window is in use and the queue is small) and
// paces KCP output at the measured send rate so it leaves in an even stream instead of
// window-sized bursts. The conference path keeps its own fixed settings.

const (
	ccTick        = 25 * time.Millisecond
	ccMinWnd      = 32
	ccMaxWnd      = 2048
	ccStartWnd    = 128
	ccMinRTTSpan  = 10 * time.Second // how long a minimum-RTT sample stays valid
	ccBwSpan      = 2 * time.Second  // bottleneck-rate estimate: max send rate over this span
	ccPaceGain    = 1.25             // pace above the measured rate so it can keep probing up
	ccMinPaceRate = 1 << 20          // bytes/s; floor so a fresh path is not starved
	ccRateWindow  = 200 * time.Millisecond
)

// ccQueueAllowance is the queueing delay tolerated above the minimum RTT.
func ccQueueAllowance(minRTT time.Duration) time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("OLCRTC_DIRECT_QDELAY_MS"))); err == nil && v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	// Measured on a 5 ms path: 10 ms kept retransmissions under 2% at the
	// highest rate (5 ms starved it, 20-40 ms let losses back up to 6-8%).
	// Higher-RTT (mobile) paths get room for their jitter.
	return max(10*time.Millisecond, minRTT/2)
}

// ccTrace (OLCRTC_DIRECT_CC_TRACE=1) logs the controller every second.
var ccTrace = os.Getenv("OLCRTC_DIRECT_CC_TRACE") == "1" //nolint:gochecknoglobals // read once

func directCCEnabled() bool {
	v := strings.TrimSpace(os.Getenv("OLCRTC_DIRECT_CC"))
	return v != "0" && !strings.EqualFold(v, "false")
}

type rateSample struct {
	at   time.Time
	rate float64
}

// ccState is the controller's arithmetic, separate from KCP for testing.
type ccState struct {
	wnd       int
	minRTT    time.Duration
	minRTTAt  time.Time
	lastAdj   time.Time
	lastBytes uint64
	lastAt    time.Time
	rates     []rateSample
	// rate measurement over ccRateWindow (per-RTT samples are too noisy)
	winAt    time.Time
	winBytes uint64
	// KCP retransmission share over the last rate window (diagnostics)
	lastOut, lastRetrans uint64
	lossRate             float64
}

// bw is the bottleneck-rate estimate: the highest send rate seen recently.
func (c *ccState) bw(now time.Time) float64 {
	keep := c.rates[:0]
	best := 0.0
	for _, r := range c.rates {
		if now.Sub(r.at) <= ccBwSpan {
			keep = append(keep, r)
			best = max(best, r.rate)
		}
	}
	c.rates = keep
	return best
}

// step takes the current smoothed RTT and the bytes sent over the direct
// path so far, and returns the window (segments) and pacing rate (bytes/s).
//
// The window follows the queueing delay (Vegas): it shrinks when the RTT
// rises more than an allowance above the path minimum and grows while it is
// in use. Pacing follows the measured rate (BBR): a spike in RTT shrinks the
// window but does not throttle the sender to a trickle.
func (c *ccState) step(now time.Time, srtt time.Duration, sentBytes, outSegs, retransSegs uint64, mss int) (int, uint32) {
	if c.wnd == 0 {
		c.wnd = ccStartWnd
		c.lastAt, c.lastBytes = now, sentBytes
		c.winAt, c.winBytes = now, sentBytes
		c.lastOut, c.lastRetrans = outSegs, retransSegs
	}
	if d := now.Sub(c.winAt); d >= ccRateWindow {
		rate := float64(sentBytes-c.winBytes) / d.Seconds()
		c.rates = append(c.rates, rateSample{at: now, rate: rate})
		c.winAt, c.winBytes = now, sentBytes
		out, re := outSegs-c.lastOut, retransSegs-c.lastRetrans
		c.lastOut, c.lastRetrans = outSegs, retransSegs
		c.lossRate = 0
		if out > 0 {
			c.lossRate = float64(re) / float64(out)
		}
		// Losses alone are not treated as congestion: mobile and Wi-Fi links
		// drop packets at random, and backing off for them starved the path
		// (0.4 vs 1.6 MB/s on an emulated LTE link). The queue (RTT) is the
		// congestion signal; KCP repairs the losses.
	}
	if srtt > 0 && (c.minRTT == 0 || srtt <= c.minRTT || now.Sub(c.minRTTAt) > ccMinRTTSpan) {
		c.minRTT, c.minRTTAt = srtt, now
	}
	// Adjust about once per RTT so each change is seen before the next.
	if srtt > 0 && now.Sub(c.lastAdj) >= max(srtt, 20*time.Millisecond) {
		elapsed := now.Sub(c.lastAt).Seconds()
		sendRate := 0.0
		if elapsed > 0 {
			sendRate = float64(sentBytes-c.lastBytes) / elapsed
		}
		c.lastAt, c.lastBytes, c.lastAdj = now, sentBytes, now
		windowRate := float64(c.wnd*mss) / srtt.Seconds()
		switch {
		case srtt > c.minRTT+ccQueueAllowance(c.minRTT):
			c.wnd = max(ccMinWnd, c.wnd*7/8)
		case sendRate >= 0.6*windowRate: // window in use, queue small: probe up
			c.wnd = min(ccMaxWnd, c.wnd+max(2, c.wnd/16))
		}
	}
	pace := max(ccPaceGain*c.bw(now), ccMinPaceRate)
	return c.wnd, uint32(min(pace, 1<<31))
}

// runDirectCC drives KCP's window and pacing while path is attached.
func (p *streamTransport) runDirectCC(path *directpath.Path) {
	if !directCCEnabled() {
		return
	}
	var st ccState
	t := time.NewTicker(ccTick)
	defer t.Stop()
	defer p.restoreKCPDefaults()
	lastLog := time.Now()
	var lastSent uint64
	for {
		select {
		case <-path.Done():
			return
		case <-p.closeCh:
			return
		case now := <-t.C:
			if p.direct.Load() != path || !path.Healthy() {
				// Traffic is back on the conference path: its own settings.
				p.restoreKCPDefaults()
				st = ccState{}
				continue
			}
			p.kcpMu.RLock()
			rt := p.kcp
			p.kcpMu.RUnlock()
			if rt == nil {
				continue
			}
			srtt := time.Duration(rt.sess.GetSRTT()) * time.Millisecond
			snmp := kcp.DefaultSnmp
			wnd, pace := st.step(now, srtt, p.directOutBytes.Load(), atomic.LoadUint64(&snmp.OutSegs), atomic.LoadUint64(&snmp.RetransSegs), kcpMTU)
			rt.sess.SetWindowSize(wnd, kcpRcvWnd)
			rt.sess.SetRateLimit(pace)
			p.ccWnd.Store(int32(wnd)) //nolint:gosec // bounded by ccMaxWnd
			if ccTrace && now.Sub(lastLog) >= time.Second {
				lastLog = now
				sent := p.directOutBytes.Load()
				logger.Infof("vp8channel: direct cc wnd=%d pace=%dKB/s srtt=%v min=%v sent=%dKB/s loss=%.1f%%", wnd, pace>>10, srtt, st.minRTT, (sent-lastSent)>>10, st.lossRate*100)
				lastSent = sent
			}
		}
	}
}

func (p *streamTransport) restoreKCPDefaults() {
	p.ccWnd.Store(0)
	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt == nil {
		return
	}
	rt.sess.SetWindowSize(envInt("OLCRTC_KCP_SNDWND", kcpSndWnd), kcpRcvWnd)
	rt.sess.SetRateLimit(0)
}

// ccWindow is the controller's current window (0 = not active), for stats.
type ccWindow = atomic.Int32
