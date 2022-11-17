package dnsquery_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/harveysanders/dnsquery"
)

func TestParseHeader(t *testing.T) {
	t.Run("parses DNS query response headers into fields", func(t *testing.T) {
		header := mustDecodeHexString(t, "b96201000001000000000000")
		want := dnsquery.DNSHeaders{
			"ID":            0xb962,
			"Flags":         0x0100,
			"NumQuestions":  0x0001,
			"NumAnswers":    0x0000,
			"NumAuth":       0x0000,
			"NumAdditional": 0x0000,
		}

		got, err := dnsquery.ParseHeader(bytes.NewBuffer(header))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("\nKey:%q\ngot:  %d\nwant: %d\n", k, got[k], v)
			}
		}
	})
}

func mustDecodeHexString(t *testing.T, hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
