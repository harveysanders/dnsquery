package dnsquery

import (
	"bufio"
	"encoding/binary"
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

// MakeQuestionHeader prepends a DNS query ID to a DNS query header.
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
func MakeQuestionHeader(queryID uint16) []byte {
	var header []byte
	parts := []uint16{
		queryID,
		0x0100, // flags
		0x0001, // num of questions
		0x0000, // num answers
		0x0000, // num auth
		0x0000, // num additional
	}
	for _, b := range parts {
		header = binary.BigEndian.AppendUint16(header, b)
	}
	return header
}

func EncodeDomainName(domainName string) string {
	return ""
}
