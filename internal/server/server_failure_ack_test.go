package server

import (
	"encoding/json"
	"io"
	"net"
	"testing"

	"github.com/xtaci/smux"
)

func TestHandleStreamWritesFailureAckOnBlockedTCP(t *testing.T) {
	ack := runBlockedRequest(t, ConnectRequest{Cmd: connectCommand, ClientID: "client-1", Addr: "198.18.0.10", Port: 443})
	if ack != 0x01 {
		t.Fatalf("ack = %#x, want failure ack", ack)
	}
}

func TestHandleStreamWritesFailureAckOnBlockedUDP(t *testing.T) {
	ack := runBlockedRequest(t, ConnectRequest{Cmd: udpCommand, ClientID: "client-1", Addr: "192.168.0.1", Port: 53})
	if ack != 0x01 {
		t.Fatalf("ack = %#x, want failure ack", ack)
	}
}

func runBlockedRequest(t *testing.T, req ConnectRequest) byte {
	t.Helper()
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	serverSess, err := smux.Server(a, smuxConfig())
	if err != nil {
		t.Fatalf("smux.Server() error = %v", err)
	}
	defer func() { _ = serverSess.Close() }()
	clientSess, err := smux.Client(b, smuxConfig())
	if err != nil {
		t.Fatalf("smux.Client() error = %v", err)
	}
	defer func() { _ = clientSess.Close() }()

	done := make(chan struct{}, 1)
	go func() {
		stream, err := serverSess.AcceptStream()
		if err == nil {
			(&Server{clientID: "client-1"}).handleStream(nil, stream)
		}
		done <- struct{}{}
	}()

	stream, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	ack := []byte{0}
	if _, err := io.ReadFull(stream, ack); err != nil {
		t.Fatalf("ReadFull(ack) error = %v", err)
	}
	<-done
	return ack[0]
}
