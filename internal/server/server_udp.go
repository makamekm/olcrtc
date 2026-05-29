package server

import (
	"net"
	"strconv"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/xtaci/smux"
)

func (s *Server) dispatchUDP(stream *smux.Stream, req ConnectRequest) {
	addr := net.JoinHostPort(req.Addr, strconv.Itoa(req.Port))
	logger.Debugf("sid=%d udp %s", stream.ID(), addr)

	if isBlockedEgressIPv4Address(req.Addr) {
		logger.Infof("sid=%d udp %s rejected: non-public egress address", stream.ID(), addr)
		_, _ = stream.Write([]byte{0x01})
		return
	}

	remote, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		logger.Infof("sid=%d udp resolve %s failed: %v", stream.ID(), addr, err)
		_, _ = stream.Write([]byte{0x01})
		return
	}
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		logger.Infof("sid=%d udp dial %s failed: %v", stream.ID(), addr, err)
		_, _ = stream.Write([]byte{0x01})
		return
	}
	defer func() { _ = conn.Close() }()

	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}

	payload, err := readLengthPrefixedDatagram(stream, 4096)
	if err != nil || len(payload) == 0 {
		logger.Infof("sid=%d udp payload read %s failed: bytes=%d err=%v", stream.ID(), addr, len(payload), err)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	logger.Debugf("sid=%d udp request %s bytes=%d", stream.ID(), addr, len(payload))
	if _, err := conn.Write(payload); err != nil {
		logger.Infof("sid=%d udp write %s failed: %v", stream.ID(), addr, err)
		return
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Infof("sid=%d udp read %s failed: %v", stream.ID(), addr, err)
		return
	}
	logger.Debugf("sid=%d udp response %s bytes=%d", stream.ID(), addr, n)
	if err := writeLengthPrefixedDatagram(stream, buf[:n]); err != nil {
		logger.Infof("sid=%d udp response write failed: %v", stream.ID(), err)
	}
}
