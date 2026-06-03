package mobile

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type androidTunReadWriter struct {
	closeOnce sync.Once
	closeErr  error
	tun       io.ReadWriteCloser
	mtu       int
	socksHost string
	socksPort int
	dnsServer string

	inPackets   uint64
	outPackets  uint64
	dnsSeen     uint64
	dnsAnswered uint64
	dnsMiss     uint64
	udpDropped  uint64
}

func newAndroidTunReadWriter(tun io.ReadWriteCloser, mtu int, socksHost string, socksPort int) *androidTunReadWriter {
	if mtu <= 0 {
		mtu = 1500
	}
	if socksHost == "" {
		socksHost = "127.0.0.1"
	}
	return &androidTunReadWriter{
		tun:       tun,
		mtu:       mtu,
		socksHost: socksHost,
		socksPort: socksPort,
		dnsServer: currentPacketFlowDNSServer(),
	}
}

func (rw *androidTunReadWriter) Read(dst []byte) (int, error) {
	if rw == nil || rw.tun == nil {
		return 0, io.ErrClosedPipe
	}
	for {
		n, err := rw.tun.Read(dst)
		if err != nil {
			return 0, err
		}
		if n == 0 || n > rw.mtu || n > len(dst) {
			continue
		}
		packet := append([]byte(nil), dst[:n]...)
		if rw.tryHandleDNS(packet) {
			continue
		}
		if isIPv4UDP(packet) {
			atomic.AddUint64(&rw.udpDropped, 1)
			if resp, ok := buildIPv4ICMPPortUnreachable(packet); ok {
				_ = rw.Respond(resp)
			}
			continue
		}
		atomic.AddUint64(&rw.inPackets, 1)
		return copy(dst, packet), nil
	}
}

func (rw *androidTunReadWriter) Write(packet []byte) (int, error) {
	if rw == nil || rw.tun == nil {
		return 0, io.ErrClosedPipe
	}
	if len(packet) == 0 {
		return 0, nil
	}
	n, err := rw.tun.Write(packet)
	if err == nil && n > 0 {
		atomic.AddUint64(&rw.outPackets, 1)
	}
	return n, err
}

func (rw *androidTunReadWriter) Respond(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	_, err := rw.Write(packet)
	return err
}

func (rw *androidTunReadWriter) Close() error {
	if rw == nil {
		return nil
	}
	rw.closeOnce.Do(func() {
		if rw.tun != nil {
			rw.closeErr = rw.tun.Close()
		}
	})
	return rw.closeErr
}

func (rw *androidTunReadWriter) tryHandleDNS(packet []byte) bool {
	if !isIPv4UDP53(packet) {
		return false
	}
	atomic.AddUint64(&rw.dnsSeen, 1)
	packetCopy := append([]byte(nil), packet...)
	go func() {
		if resp, ok := buildLocalDNSNoDataResponse(packetCopy); ok {
			atomic.AddUint64(&rw.dnsAnswered, 1)
			_ = rw.Respond(resp)
			return
		}
		select {
		case packetFlowDNSSemaphore <- struct{}{}:
			defer func() { <-packetFlowDNSSemaphore }()
		case <-time.After(packetFlowDNSAcquireTimeout):
			atomic.AddUint64(&rw.dnsMiss, 1)
			return
		}
		dnsServer := rw.dnsServer
		if dnsServer == "" {
			dnsServer = fallbackPacketFlowDNSServer
		}
		resp, _, ok := buildDNSResponseViaTCP(packetCopy, rw.socksHost, rw.socksPort, dnsServer)
		if !ok || len(resp) == 0 {
			atomic.AddUint64(&rw.dnsMiss, 1)
			if failure, failureOK := buildDNSFailureResponse(packetCopy); failureOK {
				_ = rw.Respond(failure)
			}
			return
		}
		atomic.AddUint64(&rw.dnsAnswered, 1)
		_ = rw.Respond(resp)
	}()
	return true
}

func (rw *androidTunReadWriter) DebugStats() string {
	if rw == nil {
		return "android_tun=stopped"
	}
	return fmt.Sprintf(
		"android_tun=running in=%d out=%d dns_seen=%d dns_answered=%d dns_miss=%d udp_dropped=%d",
		atomic.LoadUint64(&rw.inPackets),
		atomic.LoadUint64(&rw.outPackets),
		atomic.LoadUint64(&rw.dnsSeen),
		atomic.LoadUint64(&rw.dnsAnswered),
		atomic.LoadUint64(&rw.dnsMiss),
		atomic.LoadUint64(&rw.udpDropped),
	)
}

var errAndroidTunMissing = errors.New("android tun readwriter is not running")
