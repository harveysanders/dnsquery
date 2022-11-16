package dnsquery_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/harveysanders/dnsquery"
)

func TestRun(t *testing.T) {
	t.Skip()
	t.Run("sends a DNS query over UDP", func(t *testing.T) {
		err := dnsquery.Run()
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestMakeQuestionHeader(t *testing.T) {
	want, err := hex.DecodeString("b96201000001000000000000")
	if err != nil {
		t.Error(err)
	}

	got := dnsquery.MakeQuestionHeader(uint16(0xb962))
	if !bytes.Equal(got, want) {
		t.Errorf("got: %+v\nwant: %+v\n", got, want)
	}
}

func TestEncodeDomainName(t *testing.T) {
	t.Run("encodes a domain name with preceding segment lengths", func(t *testing.T) {
		testCases := []struct{ domain, want string }{
			{domain: "example.com", want: "\x07example\x03com\x00"},
			{domain: "google.com", want: "\x06google\x03com\x00"},
			{domain: "tacos.recipes", want: "\x05tacos\x07recipes\x00"},
		}

		for _, tc := range testCases {
			got := dnsquery.EncodeDomainName(tc.domain)
			if got != tc.want {
				t.Fatalf("Domain: %q\nwant: %q\ngot: %q", tc.domain, tc.want, got)
			}
		}

		encoded := dnsquery.EncodeDomainName("example.com")
		wantBytes, err := hex.DecodeString("076578616d706c6503636f6d00")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal([]byte(encoded), wantBytes) {
			t.Errorf("\ngot: %+v\nwant: %+v\n", []byte(encoded), wantBytes)
		}

	})
}

func TestEncodeRecordType(t *testing.T) {
	t.Run("convert DNS record type to int value", func(t *testing.T) {
		testCases := []struct {
			recType string
			want    uint16
		}{
			{recType: "A", want: 1},
			{recType: "AAAA", want: 28},
			{recType: "TXT", want: 16},
		}

		for _, tc := range testCases {

			got, err := dnsquery.EncodeRecordType(tc.recType)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("\ngot: %d\nwant: %d\n", got, tc.want)
			}
		}
	})
}

func TestMakeDNSQuery(t *testing.T) {
	t.Run("creates a DNS query for a given domain and type", func(t *testing.T) {
		wantHex := "b96201000001000000000000076578616d706c6503636f6d0000010001"

		query, err := dnsquery.MakeDNSQuery("example.com", "A", 0xb962)
		if err != nil {
			t.Fatal(err)
		}

		wantBytes, err := hex.DecodeString(wantHex)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(wantBytes, query) {
			t.Errorf("\ngot:  %+v\nwant: %+v\n", query, wantBytes)
		}
	})
}
