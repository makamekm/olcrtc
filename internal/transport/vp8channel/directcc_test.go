package vp8channel

import (
	"testing"
	"time"
)

// feed runs the controller at a constant send rate and RTT for d.
func feed(c *ccState, start time.Time, d, srtt time.Duration, rate float64, sent *uint64) (time.Time, int) {
	now := start
	var wnd int
	for t := time.Duration(0); t < d; t += ccTick {
		now = now.Add(ccTick)
		*sent += uint64(rate * ccTick.Seconds())
		wnd = c.step(now, srtt, *sent, 0, 0, kcpMTU)
	}
	return now, wnd
}

func TestDirectCCGrowsWhileTheWindowIsUsedAndTheQueueIsSmall(t *testing.T) {
	var c ccState
	var sent uint64
	now, start := feed(&c, time.Now(), 50*time.Millisecond, 10*time.Millisecond, 4e6, &sent)
	_, wnd := feed(&c, now, 2*time.Second, 10*time.Millisecond, 20e6, &sent)
	if wnd <= start {
		t.Fatalf("window did not grow: %d -> %d", start, wnd)
	}
}

func TestDirectCCHoldsTheWindowWhenItIsNotUsed(t *testing.T) {
	var c ccState
	var sent uint64
	_, wnd := feed(&c, time.Now(), 2*time.Second, 10*time.Millisecond, 0.1e6, &sent)
	if wnd != ccStartWnd {
		t.Fatalf("an idle path changed the window to %d", wnd)
	}
}

func TestDirectCCShrinksWhenTheQueueGrows(t *testing.T) {
	var c ccState
	var sent uint64
	now, before := feed(&c, time.Now(), time.Second, 5*time.Millisecond, 4e6, &sent)
	_, after := feed(&c, now, time.Second, 60*time.Millisecond, 4e6, &sent)
	if after >= before || after < ccMinWnd {
		t.Fatalf("window %d -> %d with a 55 ms queue", before, after)
	}
}

func TestDirectCCIgnoresRandomLoss(t *testing.T) {
	var c ccState
	now := time.Now()
	var sent, out, retrans uint64
	var wnd int
	for i := 0; i < 200; i++ { // 5 s at 4 MB/s, 2% retransmissions, flat RTT
		now = now.Add(ccTick)
		sent += 100_000
		out += 100
		retrans += 2
		wnd = c.step(now, 10*time.Millisecond, sent, out, retrans, kcpMTU)
	}
	if wnd < ccStartWnd {
		t.Fatalf("random loss shrank the window to %d", wnd)
	}
}

func TestDirectCCBacksOffOnALossBurst(t *testing.T) {
	var c ccState
	now := time.Now()
	var sent, out, retrans uint64
	var before, after int
	for i := 0; i < 80; i++ {
		now = now.Add(ccTick)
		sent += 25_000 // not enough to grow the window
		out += 25
		before = c.step(now, 10*time.Millisecond, sent, out, retrans, kcpMTU)
	}
	for i := 0; i < 16; i++ { // a full rate window with 30% retransmissions
		now = now.Add(ccTick)
		sent += 125_000
		out += 125
		retrans += 40
		after = c.step(now, 10*time.Millisecond, sent, out, retrans, kcpMTU)
	}
	if after >= before {
		t.Fatalf("window %d -> %d after a loss burst", before, after)
	}
}

func TestDirectCCRemembersTheCeilingAfterABurst(t *testing.T) {
	var c ccState
	now := time.Now()
	var sent, out, retrans uint64
	step := func(rate float64, loss uint64) int {
		now = now.Add(ccTick)
		sent += uint64(rate * ccTick.Seconds())
		out += 125
		retrans += loss
		return c.step(now, 10*time.Millisecond, sent, out, retrans, kcpMTU)
	}
	var wnd int
	for i := 0; i < 40; i++ {
		wnd = step(50e6, 0) // grow freely
	}
	burstAt := wnd
	for i := 0; i < 16; i++ {
		wnd = step(50e6, 40) // loss burst
	}
	for i := 0; i < 40; i++ { // 1 s clean, window in use again
		wnd = step(50e6, 0)
	}
	if float64(wnd) > 0.95*float64(burstAt) {
		t.Fatalf("window %d regrew to the burst size %d within a second", wnd, burstAt)
	}
}
