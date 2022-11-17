package dnsquery

import (
	"encoding/binary"
	"io"
)

type DNSHeaders map[string]uint16

func ParseHeader(headerBuf io.Reader) (DNSHeaders, error) {
	// read the first 12 bytes
	buf := make([]byte, 12)
	if _, err := io.ReadFull(headerBuf, buf); err != nil {
		return DNSHeaders{}, err
	}

	vSize := 2 // Each header field value is 2 bytes
	fieldOrder := []string{"ID", "Flags", "NumQuestions", "NumAnswers", "NumAuth", "NumAdditional"}
	// read each 2-byte number
	parsed := make(DNSHeaders, 6)
	for i := 0; i < len(buf); i += vSize {
		// place in a labeled map for convenience
		field := fieldOrder[i/vSize]
		parsed[field] = binary.BigEndian.Uint16(buf[i : i+vSize])
	}
	return parsed, nil
}

func ParseName() {

}

func ParseRecord() {

}
