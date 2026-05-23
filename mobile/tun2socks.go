package mobile

import (
	"fmt"
	"os"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var tun2SocksMu sync.Mutex
var tun2Socks = struct {
	running  bool
	st       *stack.Stack
	endpoint *iobased.Endpoint
	rw       *androidTunReadWriter
}{}

// StartTun2Socks routes an already-established Android VpnService TUN fd to a SOCKS5 proxy.
func StartTun2Socks(fd int64, socksHost string, socksPort int64, mtu int64) error {
	tun2SocksMu.Lock()
	defer tun2SocksMu.Unlock()

	if tun2Socks.running {
		return nil
	}
	if fd < 0 {
		return fmt.Errorf("invalid tun fd: %d", fd)
	}
	if socksHost == "" {
		socksHost = "127.0.0.1"
	}
	if socksPort <= 0 || socksPort > 65535 {
		return fmt.Errorf("invalid socks port: %d", socksPort)
	}
	if mtu <= 0 {
		mtu = 1500
	}
	clearPacketFlowDNSCache()

	tunFile := os.NewFile(uintptr(fd), "android-vpn-tun")
	if tunFile == nil {
		return fmt.Errorf("invalid tun fd: %d", fd)
	}
	rw := newAndroidTunReadWriter(tunFile, int(mtu), socksHost, int(socksPort))
	endpoint, err := iobased.New(rw, uint32(mtu), 0)
	if err != nil {
		_ = rw.Close()
		return fmt.Errorf("create android tun endpoint: %w", err)
	}

	socks, err := proxy.NewSocks5(fmt.Sprintf("%s:%d", socksHost, socksPort), "", "")
	if err != nil {
		endpoint.Close()
		_ = rw.Close()
		return fmt.Errorf("create socks proxy: %w", err)
	}
	tunnel.T().SetDialer(socks)

	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     endpoint,
		TransportHandler: tunnel.T(),
	})
	if err != nil {
		endpoint.Close()
		_ = rw.Close()
		return fmt.Errorf("create android tun stack: %w", err)
	}

	tun2Socks.rw = rw
	tun2Socks.endpoint = endpoint
	tun2Socks.st = st
	tun2Socks.running = true
	return nil
}

// StopTun2Socks stops the embedded tun2socks engine.
func StopTun2Socks() {
	tun2SocksMu.Lock()
	defer tun2SocksMu.Unlock()

	if !tun2Socks.running {
		return
	}
	clearPacketFlowDNSCache()
	if tun2Socks.rw != nil {
		_ = tun2Socks.rw.Close()
	}
	if tun2Socks.endpoint != nil {
		tun2Socks.endpoint.Close()
	}
	if tun2Socks.st != nil {
		tun2Socks.st.Close()
		tun2Socks.st.Wait()
	}
	tun2Socks.rw = nil
	tun2Socks.endpoint = nil
	tun2Socks.st = nil
	tun2Socks.running = false
}

func AndroidTun2SocksDebugStats() string {
	tun2SocksMu.Lock()
	rw := tun2Socks.rw
	tun2SocksMu.Unlock()
	if rw == nil {
		return "android_tun=stopped"
	}
	return rw.DebugStats()
}
