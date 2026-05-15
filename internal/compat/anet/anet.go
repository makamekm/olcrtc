package anet

import (
	"net"
)

const mobileInterfaceName = "rupn0"

// Interfaces returns system network interfaces.
func Interfaces() ([]net.Interface, error) {
	fallback, fallbackErr := udpLocalAddr()
	if fallbackErr == nil {
		return []net.Interface{{
			Index:        1,
			MTU:          1500,
			Name:         mobileInterfaceName,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, fallback.IP[1], fallback.IP[2], fallback.IP[3]},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		}}, nil
	}

	return net.Interfaces()
}

// InterfaceAddrs returns unicast interface addresses.
func InterfaceAddrs() ([]net.Addr, error) {
	fallback, fallbackErr := udpLocalAddr()
	if fallbackErr == nil {
		return []net.Addr{fallback}, nil
	}

	return net.InterfaceAddrs()
}

// InterfaceAddrsByInterface returns unicast addresses for a specific interface.
func InterfaceAddrsByInterface(ifi *net.Interface) ([]net.Addr, error) {
	if ifi != nil && ifi.Name == mobileInterfaceName {
		fallback, fallbackErr := udpLocalAddr()
		if fallbackErr == nil {
			return []net.Addr{fallback}, nil
		}
	}

	addrs, err := ifi.Addrs()
	if err == nil {
		return addrs, nil
	}

	fallback, fallbackErr := udpLocalAddr()
	if fallbackErr != nil {
		return nil, err
	}

	return []net.Addr{fallback}, nil
}

// InterfaceByIndex returns interface by index.
func InterfaceByIndex(index int) (*net.Interface, error) {
	if index == 1 {
		ifs, err := Interfaces()
		if err == nil && len(ifs) > 0 {
			return &ifs[0], nil
		}
	}

	return net.InterfaceByIndex(index)
}

// InterfaceByName returns interface by name.
func InterfaceByName(name string) (*net.Interface, error) {
	if name == mobileInterfaceName {
		ifs, err := Interfaces()
		if err == nil && len(ifs) > 0 {
			return &ifs[0], nil
		}
	}

	return net.InterfaceByName(name)
}

// SetAndroidVersion is kept for API compatibility with github.com/wlynxg/anet.
func SetAndroidVersion(version uint) {}

func udpLocalAddr() (*net.IPNet, error) {
	conn, err := net.Dial("udp4", "stun.rtc.yandex.net:3478")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil || addr.IP.To4() == nil || addr.IP.IsUnspecified() {
		return nil, net.InvalidAddrError("missing UDP local address")
	}

	ip := addr.IP.To4()
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
}
