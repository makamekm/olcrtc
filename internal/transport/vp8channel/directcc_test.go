package vp8channel

import (
	"testing"
	"time"
)

// feed runs the controller at a constant send rate and RTT for d.
func feed(c *ccState, start time.Time, d time.Duration, srtt time.Duration, rate float64, sent *uint64) (time.Time, int, uint32) {
	now := start
	var wnd int
	var pace uint32
	for t := time.Duration(0); t < d; t += ccTick {
		now = now.Add(ccTick)
		*sent += uint64(rate * ccTick.Seconds())
		wnd, pace = c.step(now, srtt, *sent, 0, 0, kcpMTU)
	}
	return now, wnd, pace
}

func TestDirectCCGrowsWhileTheWindowIsUsedAndTheQueueIsSmall(t *testing.T) {
	var c ccState
	var sent uint64
	now, wnd, _ := feed(&c, time.Now(), 50*time.Millisecond, 10*time.Millisecond, 4e6, &sent)
	start := wnd
	_, wnd, pace := feed(&c, now, 2*time.Second, 10*time.Millisecond, 20e6, &sent)
	if wnd <= start {
		t.Fatalf("window did not grow: %d -> %d", start, wnd)
	}
	if pace < 20e6 {
		t.Fatalf("pacing %d below the measured 20 MB/s", pace)
	}
}

func TestDirectCCShrinksWhenTheQueueGrows(t *testing.T) {
	var c ccState
	var sent uint64
	now, before, _ := feed(&c, time.Now(), time.Second, 5*time.Millisecond, 4e6, &sent)
	_, after, _ := feed(&c, now, time.Second, 60*time.Millisecond, 4e6, &sent)
	if after >= before || after < ccMinWnd {
		t.Fatalf("window %d -> %d with a 55 ms queue", before, after)
	}
}

func TestDirectCCKeepsPacingThroughAnRTTSpike(t *testing.T) {
	var c ccState
	var sent uint64
	now, _, _ := feed(&c, time.Now(), 2*time.Second, 5*time.Millisecond, 4e6, &sent)
	// A stall: RTT jumps, little gets sent. The window may shrink but the
	// pacer must stay near the measured rate, not drop to window/RTT.
	_, _, pace := feed(&c, now, 300*time.Millisecond, 400*time.Millisecond, 0.1e6, &sent)
	if pace < 4e6 {
		t.Fatalf("pacing fell to %d B/s during an RTT spike", pace)
	}
}

func TestDirectCCIgnoresLossWithoutQueue(t *testing.T) {
	var c ccState
	now := time.Now()
	var sent, out, retrans uint64
	var wnd int
	for i := 0; i < 200; i++ { // 5 s at 4 MB/s, 10% retransmissions, flat RTT
		now = now.Add(ccTick)
		sent += 100_000
		out += 100
		retrans += 10
		wnd, _ = c.step(now, 10*time.Millisecond, sent, out, retrans, kcpMTU)
	}
	if wnd < ccStartWnd {
		t.Fatalf("random loss shrank the window to %d", wnd)
	}
}

func TestDirectCCPacingHasAFloor(t *testing.T) {
	var c ccState
	_, pace := c.step(time.Now(), 0, 0, 0, 0, kcpMTU)
	if pace < ccMinPaceRate {
		t.Fatalf("pacing %d below the floor", pace)
	}
}
