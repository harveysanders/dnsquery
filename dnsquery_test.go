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

func TestHex(t *testing.T) {
	// Sample test to make sure I'm correctly decoding the hex into a byte slice
	t.Run("convert hex to []byte", func(t *testing.T) {
		hexString := "4c6561726e20476f21"
		want := []byte{76, 101, 97, 114, 110, 32, 71, 111, 33}
		_, err := hex.DecodeString(hexString)
		got := make([]byte, len(want))
		b := bytes.NewBufferString(hexString)
		d := hex.NewDecoder(b)
		d.Read(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("got:\n%q\n\nwant:\n%q", got, want)
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
			{domain: "example.com", want: "7example3com0"},
			{domain: "google.com", want: "6google3com0"},
			{domain: "tacos.recipes", want: "4tacos7recipes0"},
		}

		for _, tc := range testCases {
			got := dnsquery.EncodeDomainName(tc.domain)
			if got != tc.want {
				t.Fatalf("Domain: %q\nwant: %q\ngot: %q", tc.domain, tc.want, got)
			}
		}
	})
}
