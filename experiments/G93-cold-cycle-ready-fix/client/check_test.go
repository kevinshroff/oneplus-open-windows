package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDecoder(t *testing.T) {
	p := filepath.Join("..", "private", "adapter-model-01", "MODEL-NOT-NATIVE.bin")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	nonce := le.Uint64(b[96:])
	fmt.Println(runResult(b, nonce))
	for _, at := range []int{0, 8, 96, 104, 112, 224, 240, 44412, 44612, 44812, 44816} {
		c := append([]byte(nil), b...)
		c[at] ^= 1
		caught := false
		func() { defer func() { caught = recover() != nil }(); runResult(c, nonce) }()
		if !caught {
			t.Fatalf("accepted corrupted packet offset %d", at)
		}
	}
}
