package client

import (
	"bytes"
	"io"
	"net"
	"strings"
	"time"
)

const connectivityProbeReadLimit = 2048

var connectivityProbeHosts = map[string]struct{}{
	"connectivitycheck.gstatic.com": {},
	"clients3.google.com":           {},
	"www.google.com":                {},
}

func shouldServeConnectivityProbeLocally(targetAddr string, targetPort int) bool {
	if targetPort != 80 {
		return false
	}
	_, ok := connectivityProbeHosts[strings.ToLower(strings.TrimSpace(targetAddr))]
	return ok
}

func serveConnectivityProbeLocally(conn net.Conn, targetAddr string, targetPort int) bool {
	if !shouldServeConnectivityProbeLocally(targetAddr, targetPort) {
		return false
	}
	if _, err := conn.Write(replySuccess()); err != nil {
		return true
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, connectivityProbeReadLimit)
	_, _ = io.ReadAtLeast(conn, buf, 1)
	_ = conn.SetReadDeadline(time.Time{})
	_, _ = conn.Write(connectivityProbeResponse())
	return true
}

func connectivityProbeResponse() []byte {
	return []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

func isConnectivityProbeRequest(data []byte) bool {
	firstLineEnd := bytes.Index(data, []byte("\r\n"))
	if firstLineEnd < 0 {
		firstLineEnd = len(data)
	}
	line := strings.ToUpper(string(data[:firstLineEnd]))
	return strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "HEAD ")
}
