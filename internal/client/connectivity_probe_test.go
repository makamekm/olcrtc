package client

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestServeConnectivityProbeLocally(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	done := make(chan bool, 1)
	go func() {
		defer func() { _ = server.Close() }()
		done <- serveConnectivityProbeLocally(server, "connectivitycheck.gstatic.com", 80)
	}()

	socksReply := make([]byte, len(replySuccess()))
	if _, err := io.ReadFull(client, socksReply); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	if !bytes.Equal(socksReply, replySuccess()) {
		t.Fatalf("SOCKS reply = %v, want %v", socksReply, replySuccess())
	}
	if _, err := client.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n")); err != nil {
		t.Fatalf("write HTTP probe: %v", err)
	}
	response := make([]byte, 128)
	n, err := client.Read(response)
	if err != nil && err != io.EOF {
		t.Fatalf("read HTTP response: %v", err)
	}
	if !bytes.Contains(response[:n], []byte("204 No Content")) {
		t.Fatalf("response = %q, want 204", string(response[:n]))
	}
	if handled := <-done; !handled {
		t.Fatal("serveConnectivityProbeLocally returned false")
	}
}
