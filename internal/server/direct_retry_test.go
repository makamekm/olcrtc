package server

import (
	"testing"
	"time"
)

func TestDirectRetryIncreasesOnlyForRepeatedDegradation(t *testing.T) {
	var retry directRetryState
	at := time.Unix(1_000, 0)
	for _, wait := range []time.Duration{30, 60, 120, 120} {
		wait *= time.Second
		retry.recordClose(at, 25*time.Second, true)
		retry.recordClose(at.Add(time.Second), 20*time.Second, false)
		if !retry.coolingDown(at.Add(wait-time.Second)) || retry.coolingDown(at.Add(wait)) {
			t.Fatalf("retry window was not %s", wait)
		}
		at = at.Add(wait + time.Second)
	}
	at = at.Add(directRetryHistory)
	retry.recordClose(at, 26*time.Second, true)
	if !retry.coolingDown(at.Add(29*time.Second)) || retry.coolingDown(at.Add(30*time.Second)) {
		t.Fatal("retry cooldown did not reset after old failures expired")
	}
}
