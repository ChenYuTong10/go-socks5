package main

import (
	"log"
	"net"
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
