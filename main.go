package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

// SOCKS Protocol Version 5: https://www.rfc-editor.org/rfc/rfc1928
// Username/Password Authentication for SOCKS V5: https://www.rfc-editor.org/rfc/rfc1929

const Socks5Version = 0x05
const SubNegotiationVersion = 0x01

const GSSAPIMethod = 0x01
const UsernamePasswordMethod = 0x02
const NoAccecptableMethod = 0xFF

const AuthSuccess = 0x00
const AuthFailure = 0x01

const ConnectCmd = 0x01
const BindCmd = 0x02
const UdpCmd = 0x03

const Ipv4AddrType = 0x01
const DomainAddrType = 0x03
const Ipv6AddrType = 0x04

const SuccessConnect = 0x00
const HostUnreachable = 0x04
const NoSupportedCommand = 0x07
const NoSupportedAddressType = 0x08

var (
	ErrNoSupportedCommand     = errors.New("no supported command")
	ErrNoSupportedAddressType = errors.New("no supported address type")
)

func readNextByte(conn net.Conn) (byte, error) {
	var b [1]byte
	_, err := conn.Read(b[:])
	return b[0], err
}

func readFullBytes(conn net.Conn, buffer []byte) error {
	_, err := io.ReadFull(conn, buffer)
	return err
}

func readVersion(conn net.Conn) (byte, error) {
	return readNextByte(conn)
}

func readMethods(conn net.Conn) (byte, []byte, error) {
	nMethods, err := readNextByte(conn)
	if err != nil {
		return nMethods, nil, err
	}
	methods := make([]byte, nMethods)
	err = readFullBytes(conn, methods)
	if err != nil {
		return nMethods, methods, err
	}
	return nMethods, methods, nil
}

func containsElement[T comparable](array []T, target T) bool {
	for i := 0; i < len(array); i++ {
		if target == array[i] {
			return true
		}
	}
	return false
}

func readUsernamePassword(conn net.Conn) ([]byte, []byte, error) {
	unLength, err := readNextByte(conn)
	if err != nil {
		return nil, nil, err
	}
	username := make([]byte, unLength)
	err = readFullBytes(conn, username)
	if err != nil {
		return nil, nil, err
	}

	pwLength, err := readNextByte(conn)
	if err != nil {
		return nil, nil, err
	}
	password := make([]byte, pwLength)
	err = readFullBytes(conn, password)
	if err != nil {
		return nil, nil, err
	}
	return username, password, nil
}

func verifyUsernamePassword(username []byte, password []byte) bool {
	return true
}

type RequestOptions struct {
	Version     byte
	Command     byte
	Reserved    byte
	AddressType byte
	DestAddr    []byte
	DestPort    [2]byte
}

func readRequestDetails(conn net.Conn) (RequestOptions, error) {
	var opts RequestOptions

	version, err := readVersion(conn)
	if err != nil {
		return opts, err
	}
	opts.Version = version

	cmd, err := readNextByte(conn)
	if err != nil {
		return opts, err
	}
	if !containsElement([]byte{ConnectCmd, BindCmd, UdpCmd}, cmd) {
		return opts, ErrNoSupportedCommand
	}
	opts.Command = cmd

	rsv, err := readNextByte(conn)
	if err != nil {
		return opts, err
	}
	opts.Reserved = rsv

	atyp, err := readNextByte(conn)
	if err != nil {
		return opts, err
	}
	opts.AddressType = atyp

	switch atyp {
	case Ipv4AddrType:
		// the address is a version-4 IP address, with a length of 4 octets.
		ipv4 := make([]byte, 4)
		err = readFullBytes(conn, ipv4)
		if err != nil {
			return opts, err
		}
		opts.DestAddr = ipv4
	case DomainAddrType:
		// the first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
		domainLength, err := readNextByte(conn)
		if err != nil {
			return opts, err
		}
		domain := make([]byte, domainLength)
		err = readFullBytes(conn, domain)
		if err != nil {
			return opts, err
		}
		opts.DestAddr = domain
	case Ipv6AddrType:
		// the address is a version-6 IP address, with a length of 16 octets.
		ipv6 := make([]byte, 16)
		err = readFullBytes(conn, ipv6)
		if err != nil {
			return opts, err
		}
		opts.DestAddr = ipv6
	default:
		return opts, ErrNoSupportedAddressType
	}

	var port [2]byte
	err = readFullBytes(conn, port[:])
	if err != nil {
		return opts, err
	}
	opts.DestPort = port

	return opts, nil
}

func writeBackConn(conn net.Conn, message []byte) error {
	_, err := conn.Write(message)
	return err
}

func handler(conn net.Conn) {
	defer conn.Close()

	// Get the socks5 version
	version, err := readVersion(conn)
	if err != nil {
		log.Printf("Failed to read version from connection: %s", err)
		return
	}
	if version != Socks5Version {
		log.Printf("Socks5 version of the client mismatches: %d", version)
		return
	}

	// Get authorization methods
	_, methods, err := readMethods(conn)
	if err != nil {
		log.Printf("Failed to read message about methods from client: %s", err)
		return
	}

	// Select the authorization methods you want
	if !containsElement(methods, UsernamePasswordMethod) {
		writeBackConn(conn, []byte{Socks5Version, NoAccecptableMethod})
		return
	}
	err = writeBackConn(conn, []byte{Socks5Version, UsernamePasswordMethod})
	if err != nil {
		log.Printf("Failed to send method selection to client: %s", err)
		return
	}

	// Authorization
	subVersion, err := readVersion(conn)
	if err != nil {
		log.Printf("Failed to read sub-version from client: %s", err)
		return
	}
	if subVersion != SubNegotiationVersion {
		log.Printf("Socks5 sub-version mismatches: %x", subVersion)
		return
	}

	username, password, err := readUsernamePassword(conn)
	if err != nil {
		log.Printf("Failed to read username and password from client: %s", err)
		return
	}
	log.Printf("username: %s, password: %s", username, password)

	if !verifyUsernamePassword(username, password) {
		err = writeBackConn(conn, []byte{SubNegotiationVersion, AuthFailure})
		if err != nil {
			log.Printf("Failed to response authorization result: %s", err)
		}
		return
	}
	err = writeBackConn(conn, []byte{SubNegotiationVersion, AuthSuccess})
	if err != nil {
		log.Printf("Failed to response authorization result to client: %s", err)
		return
	}

	// accecpt request details
	opts, err := readRequestDetails(conn)
	if err != nil {
		if errors.Is(err, ErrNoSupportedAddressType) {
			err = writeBackConn(conn, []byte{Socks5Version, NoSupportedAddressType})
			if err != nil {
				log.Printf("Failed to write request result to client: %s", err)
			}
			return
		}
		log.Printf("Failed to read request information from client: %s", err)
		return
	}
	log.Printf("request options: %#v", opts)

	var target string
	if opts.AddressType == Ipv4AddrType {
		// handle ipv4 address
		target = net.JoinHostPort(
			net.IPv4(opts.DestAddr[0], opts.DestAddr[1], opts.DestAddr[2], opts.DestAddr[3]).String(),
			strconv.Itoa(int(binary.BigEndian.Uint16(opts.DestPort[:]))),
		)
	} else if opts.AddressType == DomainAddrType {
		// handle domain name address
		target = net.JoinHostPort(
			string(opts.DestAddr),
			strconv.Itoa(int(binary.BigEndian.Uint16(opts.DestPort[:]))),
		)
	} else if opts.AddressType == Ipv6AddrType {
		// handle ipv6 address
		target = net.JoinHostPort(
			net.IP(opts.DestAddr).To16().String(),
			strconv.Itoa(int(binary.BigEndian.Uint16(opts.DestPort[:]))),
		)
	}
	log.Printf("remote address: %v", target)

	// Send request to remote server
	message := &bytes.Buffer{}
	remote, err := net.Dial("tcp", target)
	local := remote.LocalAddr().(*net.TCPAddr)
	if err != nil {
		log.Printf("Failed to dial remote server: %s", err)
		message.Write([]byte{Socks5Version, HostUnreachable})
		message.Write([]byte{opts.Reserved, opts.AddressType})
		message.Write(append(local.IP, byte(local.Port)))
		err = writeBackConn(conn, message.Bytes())
		if err != nil {
			log.Printf("Failed to send request result to client: %s", err)
		}
		return
	}
	defer remote.Close()

	message.Write([]byte{Socks5Version, SuccessConnect})
	message.Write([]byte{opts.Reserved, opts.AddressType})
	message.Write(append(local.IP, byte(local.Port)))
	err = writeBackConn(conn, message.Bytes())
	if err != nil {
		log.Printf("Failed to write request result to client: %s", err)
	}

	// double transfer data between remote and client
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		log.Printf("copy from remote to client...")
		_, err = io.Copy(conn, remote)
		if err != nil {
			log.Printf("Failed to read data from remote: %s", err)
			return
		}
	}()
	go func() {
		defer wg.Done()
		log.Printf("copy from client to remote...")
		_, err = io.Copy(remote, conn)
		if err != nil {
			log.Printf("Failed to read data from client: %s", err)
			return
		}
	}()

	wg.Wait()
	log.Printf("request done!")
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
