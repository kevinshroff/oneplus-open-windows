package main

import (
	"bytes"
	"os"
	"testing"
)

func TestRequestMatchesActualC(t *testing.T) {
	for _,tc:=range []struct{name string;nonce uint64}{
		{"status-request.bin",0},{"read-request.bin",0x123456789abcdef},
	}{t.Run(tc.name,func(t *testing.T){want,err:=os.ReadFile("testdata/"+tc.name);if err!=nil {t.Fatal(err)}
		if got:=encodeRequest(tc.nonce);!bytes.Equal(got,want){t.Fatalf("request ABI: %x vs C %x",got,want)}
	})}
}
