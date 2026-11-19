package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

const (
	tlsRecordHeaderLen   = 5
	tlsHandshakeType     = 0x16
	tlsClientHelloType   = 0x01
	tlsMaxClientHelloLen = 16 * 1024
	sniPeekTimeout       = 3 * time.Second
)

var errNoSNI = errors.New("no TLS server name")

// syntheticDNSProbeNames are domains that fake-IP bypass routers route
// through their bypass; a synthetic answer for any of them means the
// configured resolver is such a router.
var syntheticDNSProbeNames = []string{"www.youtube.com", "youtube.com"} //nolint:gochecknoglobals // probe list

const syntheticDNSProbeInterval = 10 * time.Minute

// probeSyntheticDNS turns SNI routing on only where it helps. On a plain
// cloud server the resolver returns real addresses, routing by SNI would only
// add a DNS lookup to every HTTPS connection, so it stays off. Behind a
// fake-IP bypass router (custom LAN DNS) it switches on. Re-checked
// periodically in case the resolver changes behaviour.
func (s *Server) probeSyntheticDNS(ctx context.Context) {
	for {
		enabled := s.resolverReturnsSynthetic(ctx)
		if s.sniRouting.Swap(enabled) != enabled {
			logger.Infof("server: SNI routing for HTTPS to bare IPs %s (dns=%s)", map[bool]string{true: "enabled", false: "disabled"}[enabled], s.dnsServer)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(syntheticDNSProbeInterval):
		}
	}
}

func (s *Server) resolverReturnsSynthetic(ctx context.Context) bool {
	if s.resolver == nil {
		return false
	}
	for _, name := range syntheticDNSProbeNames {
		lookupCtx, cancel := context.WithTimeout(ctx, sniPeekTimeout)
		ips, err := s.resolver.LookupIP(lookupCtx, "ip4", name)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if isSyntheticIPv4Address(ip.String()) {
				return true
			}
		}
	}
	return false
}

// readClientHello reads one complete TLS record from r when it starts like a
// TLS handshake. It returns whatever bytes were read (so the caller can
// forward them unchanged) and the SNI host name when one is present.
func readClientHello(r io.Reader) ([]byte, string, error) {
	header := make([]byte, tlsRecordHeaderLen)
	n, err := io.ReadFull(r, header)
	if err != nil {
		return header[:n], "", err
	}
	if header[0] != tlsHandshakeType {
		return header, "", errNoSNI
	}
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen == 0 || recordLen > tlsMaxClientHelloLen {
		return header, "", errNoSNI
	}
	record := make([]byte, tlsRecordHeaderLen+recordLen)
	copy(record, header)
	n, err = io.ReadFull(r, record[tlsRecordHeaderLen:])
	record = record[:tlsRecordHeaderLen+n]
	if err != nil {
		return record, "", err
	}
	name, err := parseSNI(record[tlsRecordHeaderLen:])
	return record, name, err
}

// parseSNI extracts the server_name extension from a ClientHello handshake
// message (the body of a TLS handshake record).
func parseSNI(msg []byte) (string, error) {
	if len(msg) < 4 || msg[0] != tlsClientHelloType {
		return "", errNoSNI
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	body := msg[4:]
	if bodyLen < len(body) {
		body = body[:bodyLen]
	}
	// client_version(2) + random(32)
	if len(body) < 34 {
		return "", errNoSNI
	}
	p := body[34:]
	skip := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(p[i])
		}
		if len(p) < lenBytes+l {
			return false
		}
		p = p[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session_id, cipher_suites, compression_methods
		return "", errNoSNI
	}
	if len(p) < 2 {
		return "", errNoSNI
	}
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < l {
			return "", errNoSNI
		}
		ext := p[:l]
		p = p[l:]
		if extType != 0 { // server_name
			continue
		}
		if len(ext) < 2 {
			return "", errNoSNI
		}
		list := ext[2:]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:]))
			list = list[3:]
			if len(list) < nameLen {
				return "", errNoSNI
			}
			if nameType == 0 && nameLen > 0 {
				name := string(list[:nameLen])
				if net.ParseIP(name) == nil {
					return name, nil
				}
			}
			list = list[nameLen:]
		}
	}
	return "", errNoSNI
}
