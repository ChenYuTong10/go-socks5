package main

import (
	"log"
	"net"
)

func handler(conn net.Conn) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read connection: %s", err)
		return
	}
	log.Printf("Read %d bytes and the client says: %s", n, buffer[:n])
	defer conn.Close()
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
