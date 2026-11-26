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

// Delay-based window control for the direct path.
//
// KCP runs without congestion control, so over the direct path it kept its
// whole send window (384 segments, ~375 KB) in flight. On a fast path that
// is many times the bandwidth-delay product: it built a 100-400 ms queue,
// the RTT swung with it and KCP's retransmission timer fired for segments
// that were only queued - about 30% of everything sent arrived twice.
//
// While a direct path carries the tunnel, directCC keeps KCP's send window
// near the path's bandwidth-delay product (Vegas style): it shrinks when the
// smoothed RTT rises more than a small queueing allowance above the path
// minimum, or when a burst of retransmissions shows the path refusing the
// rate, and grows while the window is in use and the queue stays small. A
// window that fits the path also keeps each flush a short burst.
//
// The window is the only lever on purpose. Pacing after KCP (kcp-go's rate
// limiter or our own) delays packets that KCP has already timestamped: when
// that queue grew, retransmission timers expired before packets had even
// left, the retransmissions joined the same queue and the tunnel stalled for
// seconds. The conference path keeps its own fixed settings.

const (
	ccTick       = 25 * time.Millisecond
	ccMinWnd     = 32
	ccMaxWnd     = 2048
	ccStartWnd   = 128
	ccMinRTTSpan = 10 * time.Second // how long a minimum-RTT sample stays valid
	ccRateWindow = 200 * time.Millisecond
	// A retransmission burst this large within one rate window is not
	// random loss (mobile links lose well under 1%) but the path refusing
	// the rate - a policer or a saturated uplink, which drops without
	// queueing first.
	ccBurstLoss = 0.10
	// After a burst the window stays under 90% of the size that caused it,
	// and that ceiling rises slowly (CUBIC-like plateau), so a fixed limit
	// such as a VPS port shared by the download and the upload is not hit
	// again every few seconds.
	ccCeilBack = 0.9
	ccCeilGrow = 1.005 // per rate window, ~2.5%/s
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

// ccState is the controller's arithmetic, separate from KCP for testing.
type ccState struct {
	wnd       int
	minRTT    time.Duration
	minRTTAt  time.Time
	lastAdj   time.Time
	lastBytes uint64
	lastAt    time.Time
	// retransmission share over the last rate window
	winAt                time.Time
	lastOut, lastRetrans uint64
	lossRate             float64
	ceil                 float64 // window ceiling learned from loss bursts (0 = none)
}

// step takes the current smoothed RTT, the bytes sent over the direct path
// so far and KCP's segment counters, and returns the send window (segments).
func (c *ccState) step(now time.Time, srtt time.Duration, sentBytes, outSegs, retransSegs uint64, mss int) int {
	if c.wnd == 0 {
		c.wnd = ccStartWnd
		c.lastAt, c.lastBytes = now, sentBytes
		c.winAt = now
		c.lastOut, c.lastRetrans = outSegs, retransSegs
	}
	if now.Sub(c.winAt) >= ccRateWindow {
		c.winAt = now
		out, re := outSegs-c.lastOut, retransSegs-c.lastRetrans
		c.lastOut, c.lastRetrans = outSegs, retransSegs
		c.lossRate = 0
		if out > 0 {
			c.lossRate = float64(re) / float64(out)
		}
		// Ordinary random loss is left to KCP; only a burst backs off.
		switch {
		case out > 100 && c.lossRate > ccBurstLoss:
			c.ceil = max(ccMinWnd, ccCeilBack*float64(c.wnd))
			c.wnd = max(ccMinWnd, c.wnd*3/4)
		case c.ceil > 0:
			c.ceil *= ccCeilGrow
			if c.ceil >= ccMaxWnd {
				c.ceil = 0
			}
		}
	}
	if srtt <= 0 {
		return c.wnd
	}
	if c.minRTT == 0 || srtt <= c.minRTT || now.Sub(c.minRTTAt) > ccMinRTTSpan {
		c.minRTT, c.minRTTAt = srtt, now
	}
	// Adjust about once per RTT so each change is seen before the next.
	if now.Sub(c.lastAdj) >= max(srtt, 20*time.Millisecond) {
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
			limit := ccMaxWnd
			if c.ceil > 0 {
				limit = max(ccMinWnd, int(c.ceil))
			}
			c.wnd = max(c.wnd, min(limit, c.wnd+max(2, c.wnd/16)))
		}
	}
	return c.wnd
}

// runDirectCC drives KCP's send window while path is attached.
func (p *streamTransport) runDirectCC(path *directpath.Path) {
	if !directCCEnabled() {
		return
	}
	var st ccState
	var health directHealth
	var probe conferenceProbe
	var lastRuntime *kcpRuntime
	t := time.NewTicker(ccTick)
	defer t.Stop()
	defer func() {
		p.conferenceProbePath.CompareAndSwap(path, nil)
		if current := p.direct.Load(); current == nil || current == path {
			p.restoreKCPDefaults()
		}
	}()
	lastLog := time.Now()
	var lastSent, lastRecv uint64
	var lastNoStandby time.Time
	for {
		select {
		case <-path.Done():
			return
		case <-p.closeCh:
			return
		case now := <-t.C:
			if p.direct.Load() != path {
				return
			}
			if !path.Healthy() {
				p.conferenceProbePath.CompareAndSwap(path, nil)
				probe = conferenceProbe{}
				// Traffic is back on the conference path: its own settings.
				if st.wnd != 0 {
					p.restoreKCPDefaults()
					st = ccState{}
					health = directHealth{}
				}
				continue
			}
			p.kcpMu.RLock()
			rt := p.kcp
			p.kcpMu.RUnlock()
			if rt == nil {
				continue
			}
			if rt != lastRuntime {
				lastRuntime = rt
				p.conferenceProbePath.CompareAndSwap(path, nil)
				probe = conferenceProbe{}
				health = directHealth{}
			}
			srtt := time.Duration(rt.sess.GetSRTT()) * time.Millisecond
			if !probe.start.IsZero() {
				finished, confirmed := probe.result(now, p.conferenceIngressAt.Load())
				if !finished {
					continue
				}
				if confirmed {
					logger.Infof("vp8channel: direct path degraded (%s, KCP RTT %v); falling back to conference", probe.reason, srtt)
					path.Degrade()
					return
				}
				logger.Infof("vp8channel: conference stopped receiving during probe; keeping direct path")
				p.conferenceProbePath.CompareAndSwap(path, nil)
				probe = conferenceProbe{}
				st, health = ccState{}, directHealth{}
			}
			snmp := kcp.DefaultSnmp
			out := atomic.LoadUint64(&snmp.OutSegs)
			retrans := atomic.LoadUint64(&snmp.RetransSegs)
			wnd := st.step(now, srtt, p.directOutBytes.Load(), out, retrans, kcpMTU)
			if p.serverRole {
				if reason := health.check(now, wnd, out, retrans, rt.completedWrites.Load(), rt.pendingWrites.Load() > 0); reason != "" {
					if p.hasConferenceTraffic(now) {
						logger.Infof("vp8channel: testing conference before retiring degraded direct path (%s)", reason)
						probe = conferenceProbe{start: now, reason: reason}
						p.conferenceProbePath.Store(path)
						p.restoreKCPDefaults()
						continue
					}
					if now.Sub(lastNoStandby) >= 10*time.Second {
						logger.Infof("vp8channel: direct path degraded (%s); conference ingress is unavailable", reason)
						lastNoStandby = now
					}
				}
			}
			rt.sess.SetWindowSize(wnd, kcpRcvWnd)
			p.ccWnd.Store(int32(wnd)) //nolint:gosec // bounded by ccMaxWnd
			if ccTrace && now.Sub(lastLog) >= time.Second {
				lastLog = now
				sent, recv := p.directOutBytes.Load(), p.inBytes.Load()
				cw, rw, ss := path.SCTPInfo()
				logger.Infof("vp8channel: direct cc wnd=%d srtt=%v min=%v sent=%dKB/s recv=%dKB/s loss=%.1f%% queued=%d sctp_cwnd=%d sctp_rwnd=%d sctp_srtt=%.0fms",
					wnd, srtt, st.minRTT, (sent-lastSent)>>10, (recv-lastRecv)>>10, st.lossRate*100, path.Queued(), cw, rw, ss)
				lastSent, lastRecv = sent, recv
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
}

// ccWindow is the controller's current window (0 = not active), for stats.
type ccWindow = atomic.Int32
