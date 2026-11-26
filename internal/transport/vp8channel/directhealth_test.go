package vp8channel

import (
	"bytes"
	"testing"
	"time"
)

func TestDirectHealthRetiresConstrainedPathAfterSustainedLoss(t *testing.T) {
	var h directHealth
	at := time.Unix(100, 0)
	h.check(at, ccMinWnd, 0, 0, 0, false)
	for i := uint64(1); i <= 3; i++ {
		reason := h.check(at.Add(time.Duration(i)*time.Second), ccMinWnd, i*130, i*29, i*80_000, false)
		if (reason != "") != (i == 3) {
			t.Fatalf("sample %d: %q", i, reason)
		}
	}
}

func TestDirectHealthAllowTransientLossAndIdlePaths(t *testing.T) {
	var h directHealth
	at := time.Unix(100, 0)
	for i, repeats := range []uint64{0, 30, 31, 62, 90, 91, 92} {
		if reason := h.check(at.Add(time.Duration(i)*time.Second), ccMinWnd, uint64(i)*130, repeats, 0, false); reason != "" {
			t.Fatalf("sample %d: %s", i, reason)
		}
	}
	if reason := h.check(at.Add(30*time.Second), ccMinWnd, 780, 92, 0, false); reason != "" {
		t.Fatalf("idle path: %s", reason)
	}
}

func TestDirectHealthRetiresBlockedPayloadWhilePingsCanContinue(t *testing.T) {
	var h directHealth
	at := time.Unix(100, 0)
	for i := 0; i <= 4; i++ {
		reason := h.check(at.Add(time.Duration(i)*time.Second), ccStartWnd, uint64(i), 0, 0, true)
		if (reason != "") != (i == 4) {
			t.Fatalf("sample %d: %q", i, reason)
		}
	}
}

func TestKCPTransferResumesOnConferenceAfterDirectDataStops(t *testing.T) {
	const chunks = 64
	const chunkSize = 16 << 10
	sendOut := make(chan []byte, 1024)
	recvOut := make(chan []byte, 1024)
	delivered := make(chan []byte, chunks)
	stop := make(chan struct{})
	defer close(stop)
	sender, err := startKCP(sendOut, nil, [epochHdrLen]byte{})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.close()
	receiver, err := startKCP(recvOut, func(msg []byte) { delivered <- msg }, [epochHdrLen]byte{})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.close()

	pump := func(out <-chan []byte, dest *kcpRuntime) {
		for {
			select {
			case <-stop:
				return
			case pkt := <-out:
				dest.deliver(pkt[epochHdrLen:])
			}
		}
	}
	go pump(sendOut, receiver)
	go pump(recvOut, sender)
	sender.sess.SetWindowSize(ccMinWnd, kcpRcvWnd)

	// Keep the direct route attached, but drop its payloads. The alternate
	// conference queue remains available and has to resume the same stream.
	sender.conn.setRoute(func([]byte) bool { return true })
	sent := make(chan error, 1)
	go func() {
		for i := 0; i < chunks; i++ {
			if err := sender.send(bytes.Repeat([]byte{byte(i)}, chunkSize)); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()

	var health directHealth
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	timeout := time.After(14 * time.Second)
	for {
		select {
		case now := <-tick.C:
			reason := health.check(now, ccMinWnd, 0, 0, sender.completedWrites.Load(), sender.pendingWrites.Load() > 0)
			if reason != "" {
				sender.conn.setRoute(func([]byte) bool { return false })
				goto switched
			}
		case msg := <-delivered:
			t.Fatalf("unexpected payload on the degraded link: %d bytes", len(msg))
		case <-timeout:
			t.Fatal("guard did not recognize the blocked transfer")
		}
	}

switched:
	for i := 0; i < chunks; i++ {
		select {
		case payload := <-delivered:
			if !bytes.Equal(payload, bytes.Repeat([]byte{byte(i)}, chunkSize)) {
				t.Fatalf("chunk %d was corrupted or reordered after fallback", i)
			}
		case <-timeout:
			t.Fatalf("fallback stalled after %d of %d chunks", i, chunks)
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestConferenceProbeRequiresMoreRecentIngressBeforeRetiringDirect(t *testing.T) {
	at := time.Unix(100, 0)
	trial := conferenceProbe{start: at}
	cases := []struct {
		name                string
		now, received       time.Time
		finished, confirmed bool
	}{
		{"during probe", at.Add(time.Second), at.Add(time.Second), false, false},
		{"early keepalive only", at.Add(conferenceProbePeriod), at.Add(time.Second), true, false},
		{"old keepalive", at.Add(conferenceProbePeriod), at.Add(-time.Second), true, false},
		{"continuing ingress", at.Add(conferenceProbePeriod), at.Add(2 * time.Second), true, true},
		{"ingress went stale", at.Add(10 * time.Second), at.Add(time.Second), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finished, confirmed := trial.result(tc.now, tc.received.UnixNano())
			if finished != tc.finished || confirmed != tc.confirmed {
				t.Fatalf("got finished=%v confirmed=%v", finished, confirmed)
			}
		})
	}
}
