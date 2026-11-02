// SPDX-License-Identifier: MIT
// Offline: go run g59_hwdecode.go decode-native.go <native-power.bin>
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "one saved G59 power.bin is required")
		os.Exit(2)
	}
	b, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	r, e := decodePower(b)
	if e != nil {
		panic(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(r); e != nil {
		panic(e)
	}
}
