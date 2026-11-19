package server

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// captureClientHello returns the first TLS record a crypto/tls client sends.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // test only
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake()
		_ = client.Close()
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	hello, _, err := readClientHello(server)
	if err != nil && len(hello) == 0 {
		t.Fatalf("read ClientHello: %v", err)
	}
	return hello
}

func TestReadClientHelloExtractsServerName(t *testing.T) {
	hello := captureClientHello(t, "rr3---sn-abc.googlevideo.com")
	got, name, err := readClientHello(bytes.NewReader(hello))
	if err != nil {
		t.Fatalf("readClientHello: %v", err)
	}
	if name != "rr3---sn-abc.googlevideo.com" {
		t.Fatalf("sni = %q", name)
	}
	if !bytes.Equal(got, hello) {
		t.Fatal("readClientHello must return the record bytes unchanged for forwarding")
	}
}

func TestReadClientHelloWithoutTLSReturnsBytes(t *testing.T) {
	got, name, err := readClientHello(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")))
	if err == nil || name != "" {
		t.Fatalf("plain HTTP must not yield an SNI: name=%q err=%v", name, err)
	}
	if string(got) != "GET /" {
		t.Fatalf("consumed bytes must be returned for forwarding, got %q", got)
	}
}

func TestParseSNIRejectsTruncatedHello(t *testing.T) {
	hello := captureClientHello(t, "www.youtube.com")
	for cut := 5; cut < len(hello); cut += 7 {
		if _, err := parseSNI(hello[5:cut]); err == nil && cut < 60 {
			t.Fatalf("truncated hello (%d bytes) parsed without error", cut)
		}
	}
}

func TestShouldRouteBySNIOnlyForPublicHTTPSIPs(t *testing.T) {
	s := &Server{resolver: net.DefaultResolver}
	cases := []struct {
		addr string
		port int
		want bool
	}{
		{"142.251.20.97", 443, true},
		{"198.18.0.14", 443, false},
		{"www.youtube.com", 443, false},
		{"142.251.20.97", 80, false},
	}
	for _, c := range cases {
		if got := s.shouldRouteBySNI(ConnectRequest{Addr: c.addr, Port: c.port}); got != c.want {
			t.Fatalf("shouldRouteBySNI(%s:%d) = %v, want %v", c.addr, c.port, got, c.want)
		}
	}
}
