package server

import (
	"bytes"
	"context"
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
	if s.shouldRouteBySNI(ConnectRequest{Addr: "142.251.20.97", Port: 443}) {
		t.Fatal("SNI routing must stay off until the resolver is known to return bypass addresses")
	}
	s.sniRouting.Store(true)
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

func TestResolverReturnsSyntheticDetectsFakeIPRouter(t *testing.T) {
	fake := &Server{resolver: &net.Resolver{PreferGo: true, Dial: fakeDNSDialer("198.18.0.14")}}
	if !fake.resolverReturnsSynthetic(context.Background()) {
		t.Fatal("fake-IP resolver must enable SNI routing")
	}
	plain := &Server{resolver: &net.Resolver{PreferGo: true, Dial: fakeDNSDialer("142.250.74.110")}}
	if plain.resolverReturnsSynthetic(context.Background()) {
		t.Fatal("a resolver returning real addresses must keep SNI routing off")
	}
}

// fakeDNSDialer answers every A query with ip over an in-memory UDP-like pipe.
func fakeDNSDialer(ip string) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			buf := make([]byte, 512)
			for {
				n, err := server.Read(buf)
				if err != nil {
					return
				}
				resp := dnsAResponse(buf[:n], net.ParseIP(ip).To4())
				if resp == nil {
					return
				}
				if _, err := server.Write(resp); err != nil {
					return
				}
			}
		}()
		return &packetPipe{Conn: client}, nil
	}
}

// packetPipe marks the pipe as a packet conn so Go's resolver uses UDP framing.
type packetPipe struct{ net.Conn }

func (p *packetPipe) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

func (p *packetPipe) WriteTo(b []byte, _ net.Addr) (int, error) { return p.Write(b) }

func dnsAResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 || ip == nil {
		return nil
	}
	// Find the end of the question section (QNAME + QTYPE + QCLASS).
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	i += 5
	if i > len(query) {
		return nil
	}
	qtype := uint16(query[i-4])<<8 | uint16(query[i-3])
	resp := append([]byte(nil), query[:i]...)
	resp[2] = 0x81
	resp[3] = 0x80
	resp[6], resp[7] = 0, 0
	resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0
	if qtype != 1 {
		return resp
	}
	resp[7] = 1
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(resp, ip...)
}
