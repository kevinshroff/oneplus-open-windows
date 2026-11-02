// SPDX-License-Identifier: MIT
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	f, e := os.ReadFile(os.Args[len(os.Args)-1])
	if e != nil {
		panic(e)
	}
	var fixture map[string]string
	if e = json.Unmarshal(f, &fixture); e != nil {
		panic(e)
	}
	cases := 0
	check := func(ok bool) {
		cases++
		if !ok {
			panic(fmt.Sprintf("case%d", cases))
		}
	}
	dec := func(name string) []byte {
		b, e := hex.DecodeString(fixture[name])
		if e != nil {
			panic(e)
		}
		return b
	}
	m, l, q := dec("memory"), dec("large"), dec("irq")
	d, e := decodeResource(1, m)
	check(e == nil && d.Memory.Base == 0xa90000 && d.Memory.End == 0xa93fff && d.Memory.Bytes == 0x4000 && d.Memory.Flags == 1 && !d.PlaceholderRange)
	d, e = decodeResource(7, l)
	check(e == nil && d.Memory.Base == 0x100000000 && d.Memory.End == 0x1ffffffff && d.Memory.Bytes == 0x100000000 && d.Memory.Flags == 3)
	d, e = decodeResource(4, q)
	check(e == nil && d.Interrupt.Number == 389 && d.Interrupt.Flags == 1 && d.Interrupt.Group == 2 && d.Interrupt.Affinity == 0x8000000000000001)
	for _, x := range []struct {
		k uint32
		b []byte
		n int
	}{{1, m, 36}, {7, l, 40}, {4, q, 12}} {
		b := append(append([]byte{}, x.b...), make([]byte, x.n)...)
		d, e = decodeResource(x.k, b)
		check(e == nil && d.PlaceholderRange)
		for _, n := range []int{0, len(x.b) - 1, len(x.b) + 1, len(b) + 1} {
			v := make([]byte, n)
			copy(v, x.b)
			_, e = decodeResource(x.k, v)
			check(e != nil)
		}
		for _, off := range []int{0, 4} {
			v := append([]byte{}, x.b...)
			binary.LittleEndian.PutUint32(v[off:], 999)
			_, e = decodeResource(x.k, v)
			check(e != nil)
		}
	}
	for _, kind := range []uint32{0, 2, 3, 6, 0x8004, 0xffffffff} {
		_, e = decodeResource(kind, m)
		check(e != nil)
	}
	for _, x := range []struct{ base, end uint64 }{{2, 1}, {0, ^uint64(0)}} {
		v := append([]byte{}, m...)
		binary.LittleEndian.PutUint64(v[8:], x.base)
		binary.LittleEndian.PutUint64(v[16:], x.end)
		_, e = decodeResource(1, v)
		check(e != nil)
	}
	v := append([]byte{}, m...)
	binary.LittleEndian.PutUint64(v[8:], ^uint64(0))
	binary.LittleEndian.PutUint64(v[16:], ^uint64(0))
	d, e = decodeResource(1, v)
	check(e == nil && d.Memory.Bytes == 1)
	for _, t := range []string{"0123456789abcdef0123456789abcdef", "00000000000000000000000000000000"} {
		check(validToken(t))
	}
	for _, t := range []string{"", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0", "0123456789abcdef0123456789abcdeF", "0123456789abcdef0123456789abcde/"} {
		check(!validToken(t))
	}
	// Verify lossless compression against the independently generated C IRQ header.
	mk := func(b []byte) Descriptor {
		v, e := decodeResource(4, b)
		if e != nil {
			panic(e)
		}
		return Descriptor{Type: 4, Bytes: uint32(len(b)), Raw: hex.EncodeToString(b), Decoded: &v}
	}
	var rows []Descriptor
	want := sha256.New()
	for i := uint32(0); i < 2000; i++ {
		b := append([]byte{}, q...)
		binary.LittleEndian.PutUint32(b[12:], 389+i)
		want.Write(b)
		rows = appendDescriptor(rows, mk(b))
	}
	check(len(rows) == 1 && rows[0].Repeat == 2000)
	got := sha256.New()
	raw, _ := hex.DecodeString(rows[0].Raw)
	for i := uint32(0); i < rows[0].Repeat; i++ {
		b := append([]byte{}, raw...)
		binary.LittleEndian.PutUint32(b[12:], 389+i)
		got.Write(b)
	}
	check(hex.EncodeToString(want.Sum(nil)) == hex.EncodeToString(got.Sum(nil)))
	for _, off := range []int{8, 10, 16} {
		a := append([]byte{}, q...)
		b := append([]byte{}, q...)
		binary.LittleEndian.PutUint32(b[12:], 390)
		b[off] ^= 1
		v := appendDescriptor(nil, mk(a))
		v = appendDescriptor(v, mk(b))
		check(len(v) == 2 && v[0].Repeat == 1)
	}
	a := append(append([]byte{}, q...), make([]byte, 12)...)
	b := append([]byte{}, a...)
	binary.LittleEndian.PutUint32(b[12:], 390)
	b[len(b)-1] = 1
	vrows := appendDescriptor(nil, mk(a))
	vrows = appendDescriptor(vrows, mk(b))
	check(len(vrows) == 2)
	a = append([]byte{}, q...)
	b = append([]byte{}, q...)
	binary.LittleEndian.PutUint32(b[12:], 391)
	vrows = appendDescriptor(nil, mk(a))
	vrows = appendDescriptor(vrows, mk(b))
	check(len(vrows) == 2)
	binary.LittleEndian.PutUint32(a[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[12:], 0)
	vrows = appendDescriptor(nil, mk(a))
	vrows = appendDescriptor(vrows, mk(b))
	check(len(vrows) == 2)
	a = append([]byte{}, q...)
	b = append([]byte{}, q...)
	vrows = appendDescriptor(nil, mk(a))
	vrows[0].Repeat = 8192
	binary.LittleEndian.PutUint32(b[12:], 389+8192)
	vrows = appendDescriptor(vrows, mk(b))
	check(len(vrows) == 2)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "cases": cases, "decoder_from_actual_SDK_C_fixtures": true})
}
