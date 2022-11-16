package dnsquery

import (
	"bufio"
	"bytes"
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

// EncodeDomainName splits a domain name the QNAME for the DNS Query.
// A QNAME is "a domain name represented as a sequence of labels, where
// each label consists of a length octet followed by that
// number of octets.  The domain name terminates with the
// zero length octet for the null label of the root.  Note
// that this field may be an odd number of octets; no
// padding is used."
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
func EncodeDomainName(domainName string) string {
	parts := strings.Split(domainName, ".")
	var res strings.Builder
	for _, p := range parts {
		res.WriteByte(byte(len(p)))
		res.WriteString(p)
	}
	res.WriteByte(byte(0))
	return res.String()
}

// EncodeRecordType returns the int value for a given DNS record type.
func EncodeRecordType(queryType string) (uint16, error) {
	// https://en.wikipedia.org/wiki/List_of_DNS_record_types
	typeMap := map[string]uint16{
		"A":    1,  // Address
		"AAAA": 28, // IPv6
		"MX":   15, // Mail Server
		"NS":   2,  // Name Server
		"TXT":  16, // Text
	}

	v, ok := typeMap[queryType]
	if !ok {
		return 0, fmt.Errorf("no record type found for: %q", queryType)
	}
	return v, nil
}

func MakeDNSQuery(domain, queryType string, queryID uint16) ([]byte, error) {
	query := new(bytes.Buffer)

	// Write header bytes
	header := MakeQuestionHeader(queryID)
	binary.Write(query, binary.BigEndian, header)

	// Write domain name
	edn := EncodeDomainName(domain)
	binary.Write(query, binary.BigEndian, []byte(edn))

	// Write query type
	qType, err := EncodeRecordType(queryType)
	if err != nil {
		return query.Bytes(), err
	}
	binary.Write(query, binary.BigEndian, qType)

	// Write query class (1 for IN, INternet)
	binary.Write(query, binary.BigEndian, uint16(1))
	return query.Bytes(), nil
}
