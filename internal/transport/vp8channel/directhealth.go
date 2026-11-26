package vp8channel

import "time"

const (
	directLossInterval = time.Second
	directStalledWrite = 4 * time.Second
)

// directHealth detects sustained problems with payload delivery that ICE
// and data-channel pings can miss. The server can retire a path for both peers.
type directHealth struct {
	lastSample       time.Time
	lastOut, retrans uint64
	accepted         uint64
	blockedSince     time.Time
	badLossIntervals int
}

func (h *directHealth) check(now time.Time, wnd int, out, retrans, accepted uint64, waiting bool) string {
	if !waiting || accepted != h.accepted {
		h.blockedSince = time.Time{}
	} else if h.blockedSince.IsZero() {
		h.blockedSince = now
	} else if now.Sub(h.blockedSince) >= directStalledWrite {
		return "payload writes stalled"
	}
	h.accepted = accepted

	if h.lastSample.IsZero() {
		h.lastSample, h.lastOut, h.retrans = now, out, retrans
		return ""
	}
	if now.Sub(h.lastSample) < directLossInterval {
		return ""
	}
	sent, repeated := out-h.lastOut, retrans-h.retrans
	h.lastSample, h.lastOut, h.retrans = now, out, retrans
	if wnd > ccMinWnd || sent < 32 || repeated*100 < sent*18 {
		h.badLossIntervals = 0
		return ""
	}
	h.badLossIntervals++
	if h.badLossIntervals >= 3 {
		return "sustained retransmissions at minimum window"
	}
	return ""
}
