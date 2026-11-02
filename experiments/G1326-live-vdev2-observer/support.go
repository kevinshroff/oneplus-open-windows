package main

import (
	"fmt"
	"regexp"
	"strconv"
)

const originalSYS = "802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56"
const liveRVA = uint64(0x1ea630)
const liveCode = "7f2303d5f353bda9f55b01a9f76302a9"

func require(ok bool, why string) {
	if !ok {
		panic(why)
	}
}
func validSpan(a uint64, n uint32) bool {
	return n > 0 && n <= 32 && a >= 0xffff000000000000 && a+uint64(n) > a && a+uint64(n)-1 < 0xfffffffffffff000
}
func hex64(s string) uint64 {
	require(regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(s), "16hex address required")
	v, e := strconv.ParseUint(s, 16, 64)
	require(e == nil, "address")
	return v
}
func address(a uint64) string { return fmt.Sprintf("%016x", a) }
