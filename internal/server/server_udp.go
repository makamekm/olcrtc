package server

import (
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/xtaci/smux"
)

const udpRelayIdleTimeout = 30 * time.Second

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

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(udpRelayIdleTimeout))
			n, err := conn.Read(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
					logger.Debugf("sid=%d udp read %s ended: %v", stream.ID(), addr, err)
				}
				return
			}
			logger.Debugf("sid=%d udp response %s bytes=%d", stream.ID(), addr, n)
			_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := writeLengthPrefixedDatagram(stream, buf[:n]); err != nil {
				logger.Infof("sid=%d udp response write failed: %v", stream.ID(), err)
				return
			}
			_ = stream.SetWriteDeadline(time.Time{})
		}
	}()

	for {
		select {
		case <-done:
			return
		default:
		}
		_ = stream.SetReadDeadline(time.Now().Add(udpRelayIdleTimeout))
		payload, err := readLengthPrefixedDatagram(stream, 65535)
		if err != nil || len(payload) == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				logger.Debugf("sid=%d udp payload read %s ended: bytes=%d err=%v", stream.ID(), addr, len(payload), err)
			}
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		logger.Debugf("sid=%d udp request %s bytes=%d", stream.ID(), addr, len(payload))
		if _, err := conn.Write(payload); err != nil {
			logger.Infof("sid=%d udp write %s failed: %v", stream.ID(), addr, err)
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
}
