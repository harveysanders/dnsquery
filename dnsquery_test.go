package dnsquery_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/harveysanders/dnsquery"
)

func TestRun(t *testing.T) {
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
