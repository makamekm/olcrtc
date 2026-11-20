package directpath

import (
	"bytes"
	"context"
	"testing"
	"time"
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
