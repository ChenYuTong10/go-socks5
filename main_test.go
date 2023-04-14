package main

import (
	"net"
	"testing"
)

func TestConnection(t *testing.T) {
	conn, err := net.Dial("tcp", "127.0.0.1:9090")
	if err != nil {
		t.Errorf("Failed to connect server: %s", err)
		return
	}
	defer conn.Close()

	n, err := conn.Write([]byte("everything is ok!"))
	if err != nil {
		t.Errorf("Failed to write to server: %s", err)
		return
	}
	t.Logf("Write %d bytes to server", n)
}
