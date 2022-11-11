package dnsquery

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// https://jvns.ca/blog/2022/11/06/making-a-dns-query-in-ruby-from-scratch/

func Run() error {
	// Hex stream of example.com DNS request from Wireshark
	hexExampleComDNSQuery := "b96201000001000000000000076578616d706c6503636f6d0000010001"

	// Open UDP connection to Google's DNS server
	googleDNSAddr := "8.8.8.8:53"
	conn, err := net.Dial("udp", googleDNSAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Decode hex string into byte slice reader
	d := hex.NewDecoder(strings.NewReader(hexExampleComDNSQuery))
	// Write bytes to the DNS connection
	_, err = io.Copy(conn, d)
	if err != nil {
		return fmt.Errorf("write to conn: %w", err)
	}

	// Set 2 sec timeout
	// TODO: Figure out why connection is not closing on response
	conn.SetReadDeadline(
		time.Now().Add(time.Second * 2),
	)

	// Write response to stdout
	_, err = io.Copy(os.Stdout, bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("read from conn: %w", err)
	}
	fmt.Println("Finished")
	return nil
}
