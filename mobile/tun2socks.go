package mobile

import (
	"fmt"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

var tun2SocksMu sync.Mutex
var tun2SocksRunning bool

// StartTun2Socks routes an already-established Android VpnService TUN fd to a SOCKS5 proxy.
func StartTun2Socks(fd int64, socksHost string, socksPort int64, mtu int64) error {
	tun2SocksMu.Lock()
	defer tun2SocksMu.Unlock()

	if tun2SocksRunning {
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

	engine.Insert(&engine.Key{
		Device:     fmt.Sprintf("fd://%d", fd),
		Proxy:      fmt.Sprintf("socks5://%s:%d", socksHost, socksPort),
		MTU:        int(mtu),
		LogLevel:   "info",
		UDPTimeout: 30 * time.Second,
	})
	engine.Start()
	tun2SocksRunning = true
	return nil
}

// StopTun2Socks stops the embedded tun2socks engine.
func StopTun2Socks() {
	tun2SocksMu.Lock()
	defer tun2SocksMu.Unlock()

	if !tun2SocksRunning {
		return
	}
	engine.Stop()
	tun2SocksRunning = false
}
