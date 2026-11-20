package directpath

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

// NAT-PMP (RFC 6886): ask the home router to forward the direct-path port so
// clients on any network can reach a server behind NAT without manual setup.

const (
	natpmpPort     = 5351
	natpmpLifetime = 3600 // seconds
	natpmpTimeout  = 2 * time.Second
)

type natpmpMapping struct {
	gateway    net.IP
	externalIP string
}

func mapPortNATPMP(ctx context.Context, port int) (*natpmpMapping, error) {
	gw, err := defaultGateway()
	if err != nil {
		return nil, err
	}
	m := &natpmpMapping{gateway: gw}
	ext, err := natpmpExternalAddress(gw)
	if err != nil {
		return nil, err
	}
	m.externalIP = ext
	for _, opcode := range []byte{1, 2} { // UDP, TCP
		if err := natpmpMap(gw, opcode, port); err != nil {
			return nil, err
		}
	}
	logger.Infof("directpath: NAT-PMP gateway %s forwards udp/tcp %d (external %s)", gw, port, ext)
	go func() {
		t := time.NewTicker(natpmpLifetime / 2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				for _, opcode := range []byte{1, 2} {
					_ = natpmpRequest(gw, natpmpMapRequest(opcode, port, 0))
				}
				return
			case <-t.C:
				for _, opcode := range []byte{1, 2} {
					if err := natpmpMap(gw, opcode, port); err != nil {
						logger.Infof("directpath: NAT-PMP renew failed: %v", err)
					}
				}
			}
		}
	}()
	return m, nil
}

func natpmpMapRequest(opcode byte, port int, lifetime uint32) []byte {
	req := make([]byte, 12)
	req[1] = opcode
	binary.BigEndian.PutUint16(req[4:6], uint16(port)) //nolint:gosec // port validated by caller
	binary.BigEndian.PutUint16(req[6:8], uint16(port)) //nolint:gosec // same external port requested
	binary.BigEndian.PutUint32(req[8:12], lifetime)
	return req
}

func natpmpMap(gw net.IP, opcode byte, port int) error {
	resp, err := natpmpRoundTrip(gw, natpmpMapRequest(opcode, port, natpmpLifetime))
	if err != nil {
		return err
	}
	if len(resp) < 16 || resp[1] != 128+opcode {
		return fmt.Errorf("unexpected NAT-PMP map response %x", resp)
	}
	if code := binary.BigEndian.Uint16(resp[2:4]); code != 0 {
		return fmt.Errorf("NAT-PMP map refused, result code %d", code)
	}
	if ext := int(binary.BigEndian.Uint16(resp[10:12])); ext != port {
		return fmt.Errorf("NAT-PMP mapped external port %d instead of %d", ext, port)
	}
	return nil
}

func natpmpExternalAddress(gw net.IP) (string, error) {
	resp, err := natpmpRoundTrip(gw, []byte{0, 0})
	if err != nil {
		return "", err
	}
	if len(resp) < 12 || resp[1] != 128 || binary.BigEndian.Uint16(resp[2:4]) != 0 {
		return "", fmt.Errorf("unexpected NAT-PMP address response %x", resp)
	}
	return net.IP(resp[8:12]).String(), nil
}

func natpmpRequest(gw net.IP, req []byte) error {
	_, err := natpmpRoundTrip(gw, req)
	return err
}

func natpmpRoundTrip(gw net.IP, req []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw, Port: natpmpPort})
	if err != nil {
		return nil, fmt.Errorf("NAT-PMP dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(natpmpTimeout))
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("NAT-PMP write: %w", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("NAT-PMP read: %w", err)
	}
	return buf[:n], nil
}

// defaultGateway reads the IPv4 default route from /proc/net/route (Linux;
// servers run there).
func defaultGateway() (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" || fields[2] == "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), nil
	}
	return nil, errors.New("no IPv4 default gateway")
}
