package main

import (
	"bytes"
	"fmt"
)

func validateBootHeader(b []byte, prefix uint64) error {
	if len(b) < 4096 || !bytes.Equal(b[:8], []byte("ANDROID!")) || u32(b, 12) != 0 || u32(b, 20) != 1580 || u32(b, 40) != 3 {
		return fmt.Errorf("only current Android v3 firmware-container shape is supported")
	}
	if !bytes.Equal(b[24:40], make([]byte, 16)) || u32(b, 8) == 0 || prefix < 4096 || uint64(u32(b, 8)) > prefix-4096 {
		return fmt.Errorf("boot container reserved fields or payload bounds")
	}
	return nil
}
