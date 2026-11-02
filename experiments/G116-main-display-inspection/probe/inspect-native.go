// Offline decoder: go run g116_decode.go inspect-native.go CAPTURE.bin
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("one raw capture path is required")
	}
	b, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	if len(b) != captureBytes {
		panic("raw capture size")
	}
	r, e := decodeCapture(b, le.Uint64(b[80:]))
	if e != nil {
		panic(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(r); e != nil {
		panic(fmt.Sprint(e))
	}
}
