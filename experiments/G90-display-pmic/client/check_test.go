package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestObservedPackets(t *testing.T) {
	for i := 1; i <= 2; i++ {
		b, e := os.ReadFile(fmt.Sprintf("../../../evidence/G90/pmic-%d.bin", i))
		if e != nil {
			t.Fatal(e)
		}
		if len(b) != 1744 {
			t.Fatal("packet ABI")
		}
		status(b)
		if u(b, 96) != 0 || b[164] != 3 || !bytes.Equal(b[165:173], []byte{8, 7, 0, 0, 7, 7, 0, 0}) || u(b, 1716) != 1 || u(b, 1720) != uint32(i) {
			t.Fatal("observer packet changed")
		}
	}
}
