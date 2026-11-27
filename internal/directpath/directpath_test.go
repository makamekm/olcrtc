package directpath

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestDirectPathCarriesFramesBothWays(t *testing.T) {
	t.Setenv(EnvPort, "47391")
	t.Setenv(EnvNATPMP, "0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := ServerFromEnv(ctx)
	if err != nil || srv == nil {
		t.Fatalf("server: %v", err)
	}
	offerer, offer, err := NewOfferer(ctx)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	serverPath, answer, err := srv.Answer(ctx, offer)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	gotOnServer := make(chan []byte, 1)
	serverPath.OnFrame(func(b []byte) { gotOnServer <- append([]byte(nil), b...) })
	clientPath, err := offerer.Finish(ctx, answer)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	defer clientPath.Close()
	defer serverPath.Close()
	gotOnClient := make(chan []byte, 1)
	clientPath.OnFrame(func(b []byte) { gotOnClient <- append([]byte(nil), b...) })

	if !clientPath.Send([]byte("to-server")) {
		t.Fatal("client could not send over a fresh path")
	}
	select {
	case got := <-gotOnServer:
		if !bytes.Equal(got, []byte("to-server")) {
			t.Fatalf("server got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never received the frame")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !serverPath.Healthy() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !serverPath.Send([]byte("to-client")) {
		t.Fatal("server could not send back")
	}
	select {
	case got := <-gotOnClient:
		if !bytes.Equal(got, []byte("to-client")) {
			t.Fatalf("client got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never received the frame")
	}

	clientPath.Close()
	if clientPath.Healthy() || clientPath.Send([]byte("x")) {
		t.Fatal("a closed path must refuse frames so traffic falls back")
	}
}

func TestServerDisabledWithoutPort(t *testing.T) {
	t.Setenv(EnvPort, "")
	srv, err := ServerFromEnv(context.Background())
	if srv != nil || err != nil {
		t.Fatalf("expected disabled server, got %v %v", srv, err)
	}
}

func TestAnswerAdvertisesThePublicAddressOnTheForwardedPort(t *testing.T) {
	t.Setenv(EnvPort, "40777")
	t.Setenv(EnvPublicIP, "203.0.113.7")
	t.Setenv(EnvNATPMP, "0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := ServerFromEnv(ctx)
	if err != nil || s == nil {
		t.Fatalf("server: %v", err)
	}
	o, offer, err := NewOfferer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Abort()
	p, answer, err := s.Answer(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if !strings.Contains(answer, "203.0.113.7 40777 typ host\r\n") ||
		!strings.Contains(answer, "203.0.113.7 40777 typ host tcptype passive") {
		t.Fatalf("public candidate missing:\n%s", answer)
	}
	for _, l := range strings.Split(answer, "\r\n") {
		if strings.Contains(l, "203.0.113.7") && !strings.Contains(l, " 40777 ") {
			t.Fatalf("public address on another port: %s", l)
		}
	}
	// The answer must still be acceptable to the client.
	if err := o.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatalf("client rejects answer: %v", err)
	}
}

func TestDirectPathFallsBackToTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	engine := webrtc.SettingEngine{}
	engine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeTCP4})
	engine.SetICETCPMux(webrtc.NewICETCPMux(nil, listener, 64))
	tuneSCTP(&engine)
	server := &Server{
		api:  webrtc.NewAPI(webrtc.WithSettingEngine(engine)),
		port: listener.Addr().(*net.TCPAddr).Port,
	}

	offerer, offer, err := NewOfferer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer offerer.Abort()
	serverPath, answer, err := server.Answer(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	defer serverPath.Close()

	toServer := make(chan string, 1)
	serverPath.OnFrame(func(frame []byte) { toServer <- string(frame) })
	clientPath, err := offerer.Finish(ctx, answer)
	if err != nil {
		t.Fatalf("TCP-only negotiation: %v", err)
	}
	defer clientPath.Close()
	toClient := make(chan string, 1)
	clientPath.OnFrame(func(frame []byte) { toClient <- string(frame) })

	if !clientPath.Send([]byte("to-server")) {
		t.Fatal("client could not send over TCP")
	}
	select {
	case frame := <-toServer:
		if frame != "to-server" {
			t.Fatalf("server got %q", frame)
		}
	case <-ctx.Done():
		t.Fatal("server never received the TCP frame")
	}
	if !serverPath.Send([]byte("to-client")) {
		t.Fatal("server could not send over TCP")
	}
	select {
	case frame := <-toClient:
		if frame != "to-client" {
			t.Fatalf("client got %q", frame)
		}
	case <-ctx.Done():
		t.Fatal("client never received the TCP frame")
	}
}

func TestPublicCandidatesPreferUDPAndThenAddressOrder(t *testing.T) {
	got := publicCandidates(" 192.0.2.1, bad, 192.0.2.2, 192.0.2.1 ", 40401)
	want := []string{
		"a=candidate:7001 1 udp 2130680831 192.0.2.1 40401 typ host",
		"a=candidate:7002 1 tcp 1671404543 192.0.2.1 40401 typ host tcptype passive",
		"a=candidate:7003 1 udp 2130680575 192.0.2.2 40401 typ host",
		"a=candidate:7004 1 tcp 1671404287 192.0.2.2 40401 typ host tcptype passive",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDirectPathUsesReachableFallbackAddress(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var reachable string
	for _, addr := range addrs {
		if network, ok := addr.(*net.IPNet); ok && network.IP.To4() != nil && !network.IP.IsLoopback() {
			reachable = network.IP.String()
			break
		}
	}
	if reachable == "" {
		t.Skip("no non-loopback IPv4 address")
	}

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	engine := webrtc.SettingEngine{}
	engine.SetICEUDPMux(webrtc.NewICEUDPMux(nil, listener))
	engine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	server := &Server{
		api:      webrtc.NewAPI(webrtc.WithSettingEngine(engine)),
		port:     listener.LocalAddr().(*net.UDPAddr).Port,
		publicIP: "192.0.2.1," + reachable,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	offerer, offer, err := NewOfferer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer offerer.Abort()
	serverPath, answer, err := server.Answer(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	defer serverPath.Close()

	var lines []string
	for _, line := range strings.Split(answer, "\r\n") {
		if !strings.HasPrefix(line, "a=candidate:") || strings.HasPrefix(line, "a=candidate:7001 ") || strings.HasPrefix(line, "a=candidate:7003 ") {
			lines = append(lines, line)
		}
	}
	path, err := offerer.Finish(ctx, strings.Join(lines, "\r\n"))
	if err != nil {
		t.Fatalf("could not connect through the second address: %v", err)
	}
	defer path.Close()
	pair, err := offerer.pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil || pair.Remote.Address != reachable {
		t.Fatalf("selected pair = %v, error = %v, want second address %s", pair, err, reachable)
	}
}
