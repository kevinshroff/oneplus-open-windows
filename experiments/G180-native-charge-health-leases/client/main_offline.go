//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("one saved snapshot required")
	}
	b, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	r, e := decode(b)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(r)
}
