package main

import (
	"net/http"
	_ "net/http/pprof" //nolint:gosec // opt-in diagnostics listener
	"os"
)

// OLCRTC_PPROF=127.0.0.1:6060 serves Go profiles for performance work.
func init() {
	if addr := os.Getenv("OLCRTC_PPROF"); addr != "" {
		go func() { _ = http.ListenAndServe(addr, nil) }() //nolint:gosec // local diagnostics only
	}
}
