package vp8channel

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"
)

func servedFrame(epoch uint32) []byte {
	f := make([]byte, epochHdrLen+4)
	binary.BigEndian.PutUint32(f[servedEpochOff:servedMarkOff], epoch)
	binary.BigEndian.PutUint16(f[servedMarkOff:servedMarkOff+2], servedMarker)
	return f
}

// shift moves the detector's clock back so tests need not sleep 12 s.
func shift(tr *streamTransport, d time.Duration) {
	if v := tr.foreignSince.Load(); v != 0 {
		tr.foreignSince.Store(v - int64(d))
	}
}

func TestKeyInUseFiresOnceWhenServerServesAnotherDevice(t *testing.T) {
	tr := &streamTransport{}
	tr.setLocalEpoch(0x1111)
	var fired atomic.Int32
	tr.SetBusyCallback(func() { fired.Add(1) })

	for i := 0; i < 3; i++ {
		if !tr.servedOtherSession(servedFrame(0x2222)) {
			t.Fatal("frame for another device must be dropped")
		}
	}
	shift(tr, keyInUseAfter)
	tr.servedOtherSession(servedFrame(0x2222))
	tr.servedOtherSession(servedFrame(0x2222))
	time.Sleep(50 * time.Millisecond)
	if fired.Load() != 1 {
		t.Fatalf("busy fired %d times, want 1", fired.Load())
	}
}

func TestKeyInUseIgnoresOwnEpochsAndQuickTakeover(t *testing.T) {
	tr := &streamTransport{}
	var fired atomic.Int32
	tr.SetBusyCallback(func() { fired.Add(1) })

	// Our previous session (carrier reconnect) is not another device.
	tr.setLocalEpoch(0x1111)
	tr.setLocalEpoch(0x3333)
	tr.servedOtherSession(servedFrame(0x1111))
	shift(tr, keyInUseAfter)
	tr.servedOtherSession(servedFrame(0x1111))

	// A previous process of this device is served for a few seconds, then
	// the server switches to us: no error, even if old frames trail later.
	tr.servedOtherSession(servedFrame(0x9999))
	shift(tr, 4*time.Second)
	if tr.servedOtherSession(servedFrame(0x3333)) {
		t.Fatal("frame for our session must be delivered")
	}
	tr.servedOtherSession(servedFrame(0x9999))
	shift(tr, 5*time.Second)
	tr.servedOtherSession(servedFrame(0x9999))

	// A server without a peer stamps 0.
	tr.servedOtherSession(servedFrame(0))
	time.Sleep(50 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatalf("busy fired %d times, want 0", fired.Load())
	}
}
