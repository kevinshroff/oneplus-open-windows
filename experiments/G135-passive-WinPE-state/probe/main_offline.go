// Decode an already retained capture; no native API or hardware access.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 { panic("capture-file nonce-hex") }
	b, e := os.ReadFile(os.Args[1]); if e != nil { panic(e) }
	n, e := strconv.ParseUint(os.Args[2],16,64); if e != nil { panic(e) }
	v, e := decodeCapture(b,n); if e != nil { panic(e) }
	if e = json.NewEncoder(os.Stdout).Encode(v); e != nil { panic(fmt.Sprint(e)) }
}
