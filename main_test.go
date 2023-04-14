package main

import (
	"io"
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

func TestSocks5(t *testing.T) {
	conn, err := net.Dial("tcp", "127.0.0.1:9090")
	if err != nil {
		t.Errorf("Failed to connect server: %s", err)
		return
	}
	defer conn.Close()

	/* First negotiation request format
	   +----+----------+----------+
	   |VER | NMETHODS | METHODS  |
	   +----+----------+----------+
	   | 1  |    1     | 1 to 255 |
	   +----+----------+----------+
	*/

	/*
		X'00' NO AUTHENTICATION REQUIRED
		X'01' GSSAPI
		X'02' USERNAME/PASSWORD
		X'03' to X'7F' IANA ASSIGNED
		X'80' to X'FE' RESERVED FOR PRIVATE METHODS
		X'FF' NO ACCEPTABLE METHODS
	*/
	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	if err != nil {
		t.Errorf("Failed to send socks5 request: %s", err)
		return
	}
	/* First negotiation response format
	+----+--------+
	|VER | METHOD |
	+----+--------+
	| 1  |   1    |
	+----+--------+
	*/
	buffer := make([]byte, 2)
	_, err = io.ReadFull(conn, buffer)
	if err != nil {
		t.Errorf("Failed to read socks5 response: %s", err)
		return
	}
	if buffer[0] != 0x05 {
		t.Errorf("Socks5 version mismatch: get %d", buffer[0])
		return
	}
	if buffer[1] == 0xff {
		t.Errorf("No accepcted authorization method")
		return
	}
	t.Logf("Selected method: %d", buffer[1])
}
