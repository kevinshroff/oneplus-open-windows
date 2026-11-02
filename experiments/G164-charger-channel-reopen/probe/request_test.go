package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestRequestMatchesActualC(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nonce uint64
	}{
		{"status-request.bin", 0}, {"read-request.bin", 0x123456789abcdef},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile("testdata/" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if got := encodeRequest(tc.nonce); !bytes.Equal(got, want) {
				t.Fatalf("request ABI: %x vs C %x", got, want)
			}
		})
	}
}

func TestControlCodesMatchActualC(t *testing.T) {
	b, e := os.ReadFile("testdata/control-codes.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]uint32
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if len(v) != 3 || v["status"] != ioctlStatus || v["read"] != ioctlRead || v["result"] != ioctlResult {
		t.Fatal(v)
	}
}
