// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	b, e := os.ReadFile(os.Args[len(os.Args)-1])
	if e != nil {
		panic(e)
	}
	cases := 0
	check := func(v bool) {
		cases++
		if !v {
			panic(fmt.Sprintf("G63 decoder case%d", cases))
		}
	}
	d, e := decodeCapture(b)
	check(e == nil && d["resource_shape_matches_pilot"] == true && d["native_resource_handoff_qualified_by_decode_alone"] == false && d["actual_IRQ_delivery_qualified"] == false)
	raw := d["raw"].([]map[string]any)
	tr := d["translated"].([]map[string]any)
	check(raw[1]["vector"] == uint32(389) && tr[1]["vector"] == uint32(0x2ff) && tr[1]["level"] == uint16(6) && tr[1]["affinity"] == uint64(0xff))
	for _, n := range []int{0, 607, 609, 1000} {
		v := make([]byte, n)
		copy(v, b)
		_, e = decodeCapture(v)
		check(e != nil)
	}
	for _, off := range []int{0, 4, 8, 16, 20, 24, 28, 32, 36, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92} {
		v := append([]byte{}, b...)
		v[off] ^= 1
		_, e = decodeCapture(v)
		check(e != nil)
	}
	for _, off := range []int{40, 48} {
		v := append([]byte{}, b...)
		binary.LittleEndian.PutUint32(v[off:], 0)
		_, e = decodeCapture(v)
		check(e != nil)
	}
	for _, off := range []int{44, 52} {
		v := append([]byte{}, b...)
		binary.LittleEndian.PutUint32(v[off:], 999)
		_, e = decodeCapture(v)
		check(e != nil)
	}
	for _, base := range []int{96, 352} {
		for _, off := range []int{0, 1, 2, 4, 12, 20, 32, 33, 34, 52, 64, 255} {
			v := append([]byte{}, b...)
			v[base+off] ^= 1
			_, e = decodeCapture(v)
			check(e != nil)
		}
	}
	v := append([]byte{}, b...)
	v[96+32+8] ^= 1
	_, e = decodeCapture(v)
	check(e != nil)
	v = append([]byte{}, b...)
	binary.LittleEndian.PutUint32(v[352+32+8:], 389)
	d, e = decodeCapture(v)
	check(e == nil && d["resource_shape_matches_pilot"] == true)
	for _, token := range []string{"00000000000000000000000000000000", "00000000000000000000000000000000"} {
		check(tokenOK(token))
	}
	for _, token := range []string{"", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0", "0123456789abcdef0123456789abcdeF", "0123456789abcdef0123456789abcde/"} {
		check(!tokenOK(token))
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "cases": cases, "C_fixture_matches_Go_decoder": true, "translated_vector_not_assumed_equal_to_raw": true, "native_operations": 0})
}
