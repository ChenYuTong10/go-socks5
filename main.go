package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
)

func handler(conn net.Conn) {
	defer conn.Close()

	// Get the socks5 version
	var version [1]byte
	_, err := conn.Read(version[:])
	if err != nil {
		log.Printf("Failed to read version from connection: %s", err)
		return
	}
	if version[0] != 0x05 {
		log.Printf("Socks5 version of the client mismatches: %d", version[0])
		return
	}

	// Get the numbers of authorization methods
	var nMethods [1]byte
	_, err = conn.Read(nMethods[:])
	if err != nil {
		log.Printf("Failed to read the numbers of methods from connection: %s", err)
		return
	}

	// Get these methods
	methods := make([]byte, nMethods[0])
	_, err = conn.Read(methods)
	if err != nil {
		log.Printf("Failed to read methods from connection: %s", err)
		return
	}

	// Select the authorization methods you want
	if _, err = conn.Write([]byte{0x05, 0x02}); err != nil {
		log.Printf("Failed to write methods to client: %s", err)
		return
	}

	// Authorization
	var subVersion [1]byte
	_, err = conn.Read(subVersion[:])
	if err != nil {
		log.Printf("Failed to read sub-version from connection: %s", err)
		return
	}
	if subVersion[0] != 0x01 {
		log.Printf("Socks5 sub-version mismatches: %x", subVersion[0])
		return
	}

	var unLength [1]byte
	_, err = conn.Read(unLength[:])
	if err != nil {
		log.Printf("Failed to read username length from connection: %s", err)
		return
	}
	username := make([]byte, unLength[0])
	_, err = io.ReadFull(conn, username)
	if err != nil {
		log.Printf("Failed to read username from connection: %s", err)
		return
	}

	var pwLength [1]byte
	_, err = conn.Read(pwLength[:])
	if err != nil {
		log.Printf("Failed to read password length from connection: %s", err)
		return
	}
	password := make([]byte, pwLength[0])
	_, err = io.ReadFull(conn, password)
	if err != nil {
		log.Printf("Failed to read password from connection: %s", err)
		return
	}
	log.Printf("username: %s, password: %s", username, password)

	/*If the username and password is verified, write this back
	+----+--------+
	|VER | STATUS |
	+----+--------+
	| 1  |   1    |
	+----+--------+
	*/
	_, err = conn.Write([]byte{0x01, 0x00})
	if err != nil {
		log.Printf("Failed to write verification to client: %s", err)
		return
	}

	/* Request reply format
	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/
	request := make([]byte, 1024)
	_, err = conn.Read(request)
	if err != nil {
		log.Printf("Failed to read request information from client: %s", err)
		return
	}
	if request[0] != 0x05 {
		log.Printf("Socks5 version mismatches: %x", request[0])
		return
	}
	if request[1] != 0x01 {
		_, err = conn.Write(append([]byte{0x05, 0x07, 0x00}, request[4:]...))
		if err != nil {
			log.Printf("Failed to write request result to client: %s", err)
		}
		return
	}
	if request[3] != 0x03 {
		_, err = conn.Write(append([]byte{0x05, 0x08, 0x00}, request[4:]...))
		if err != nil {
			log.Printf("Failed to write request result to client: %s", err)
		}
		return
	}
	domainLen := request[4]
	domain := request[5 : 5+domainLen]
	log.Printf("domain name: %s", domain)

	port := binary.BigEndian.Uint16(request[5+domainLen:])
	log.Printf("port: %d", port)

	addr := net.JoinHostPort(string(domain), strconv.Itoa(int(port)))
	log.Printf("remote address: %s", addr)

	// Send request to remote address
	remote, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to dial remote server: %s", err)
		_, err = conn.Write(append([]byte{0x05, 0x04, 0x00}, request[4:]...))
		if err != nil {
			log.Printf("Failed to write request result to client: %s", err)
		}
		return
	}
	defer remote.Close()

	_, err = conn.Write(append([]byte{0x05, 0x00, 0x00}, request[4:]...))
	if err != nil {
		log.Printf("Failed to write request result to client: %s", err)
	}

	go func() {
		_, err = io.Copy(conn, remote)
		if err != nil {
			log.Printf("Failed to read data from remote: %s", err)
			return
		}
	}()

	_, err = io.Copy(remote, conn)
	if err != nil {
		log.Printf("Failed to read data from connection: %s", err)
		return
	}
}

func main() {
	listener, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Listening to the port 9090")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept a connection: %s", err)
			continue
		}

		go handler(conn)
	}
}
