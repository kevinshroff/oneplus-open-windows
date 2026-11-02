// SPDX-License-Identifier: MIT
// Offline: go run g95_hwdecode.go decode-native.go <native-power.bin>
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 && !(len(os.Args) == 3 && os.Args[1] == "--pmic") {
		fmt.Fprintln(os.Stderr, "one saved G95 power.bin is required")
		os.Exit(2)
	}
	b, e := os.ReadFile(os.Args[len(os.Args)-1])
	if e != nil {
		panic(e)
	}
	var r map[string]any
	if len(os.Args) == 3 {
		r, e = decodePMIC(b)
	} else {
		r, e = decodePower(b)
	}
	if e != nil {
		panic(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(r); e != nil {
		panic(e)
	}
}
