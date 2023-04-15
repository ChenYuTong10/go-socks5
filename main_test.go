package main

import (
	"bytes"
	"encoding/binary"
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

	/* Username and password negotiation format
	+----+------+----------+------+----------+
	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	+----+------+----------+------+----------+
	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	+----+------+----------+------+----------+
	*/

	const username = "zhangsan"
	const password = "123456"

	b := &bytes.Buffer{}
	b.WriteByte(0x01)
	b.WriteByte(byte(len(username)))
	b.WriteString(username)
	b.WriteByte(byte(len(password)))
	b.WriteString(password)

	_, err = conn.Write(b.Bytes())
	if err != nil {
		t.Errorf("Failed to send username and password to server: %s", err)
		return
	}

	verification := make([]byte, 2)
	_, err = io.ReadFull(conn, verification)
	if err != nil {
		t.Errorf("Failed to read verification from server: %s", err)
		return
	}
	if verification[1] != 0x00 {
		t.Errorf("Authorization failed")
		return
	}
	t.Log("Authorization success")

	/* Request details
		    +----+-----+-------+------+----------+----------+
	        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	        +----+-----+-------+------+----------+----------+
	        | 1  |  1  | X'00' |  1   | Variable |    2     |
	        +----+-----+-------+------+----------+----------+

	*/
	/*

		o  VER    protocol version: X'05'
		o  CMD
			o  CONNECT X'01'
			o  BIND X'02'
			o  UDP ASSOCIATE X'03'
		o  RSV    RESERVED
		o  ATYP   address type of following address
			o  IP V4 address: X'01'
			o  DOMAINNAME: X'03'
			o  IP V6 address: X'04'
		o  DST.ADDR       desired destination address
		o  DST.PORT desired destination port in network octet
		             order
	*/
	domain := "chouyatou.live"
	port := 80

	b = &bytes.Buffer{}
	b.WriteByte(0x05)
	b.WriteByte(0x01) // CONNECT
	b.WriteByte(0x00) // RESERVED
	b.WriteByte(0x03) // DOMAIN NAME
	b.WriteByte(byte(len(domain)))
	b.WriteString(domain)
	b.WriteByte(byte(port >> 8))
	b.WriteByte(byte(port))

	_, err = conn.Write(b.Bytes())
	if err != nil {
		t.Errorf("Failed to write request infomation to server: %s", err)
		return
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		t.Errorf("Failed to read response from server: %s", err)
		return
	}
	switch response[1] {
	case 0x00:
		t.Log("Succeed to connect remote server")
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: chouyatou.live\r\n\r\n"))
		buffer = make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			t.Errorf("Failed to read response from server: %s", err)
			return
		}
		t.Log(string(buffer[:n]))
		conn.Close()
	case 0x04:
		t.Error("Host unreachable")
	case 0x07:
		t.Error("Command not supported")
	case 0x08:
		t.Error("Address type not supported")
	default:
		t.Errorf("Unknown reason: %x", response[1])
	}

}

func TestBigEndian(t *testing.T) {
	port := 443

	t.Logf("bytes 443: %x", byte(port))
	t.Logf("byte high 8 bits: %x", byte(port>>8))
	t.Logf("byte low 8 bits: %x", byte(port))

	_port := binary.BigEndian.Uint16([]byte{0x01, 0xbb})
	t.Logf("after convert: %d", _port)
}
