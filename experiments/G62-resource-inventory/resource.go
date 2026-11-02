// SPDX-License-Identifier: MIT
// Allocation headers follow the pinned SDK26100 cfgmgr32.h (pack1). Keep raw
// bytes for every descriptor; an unsupported/malformed descriptor is not proof
// of an absent hardware owner. This decodes ALLOC/BOOT, never requirements.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

type Memory struct {
	Base     uint64 `json:"base"`
	End      uint64 `json:"end"`
	Bytes    uint64 `json:"bytes"`
	Flags    uint32 `json:"flags"`
	Reserved uint32 `json:"reserved"`
}
type Interrupt struct {
	Number   uint32 `json:"number"`
	Flags    uint16 `json:"flags"`
	Group    uint16 `json:"group"`
	Affinity uint64 `json:"affinity"`
}
type Decoded struct {
	Kind             string     `json:"kind"`
	PlaceholderRange bool       `json:"placeholder_range"`
	Memory           *Memory    `json:"memory,omitempty"`
	Interrupt        *Interrupt `json:"interrupt,omitempty"`
}

func decodeResource(kind uint32, b []byte) (Decoded, error) {
	var d Decoded
	var header, rangeSize int
	switch kind {
	case 1:
		d.Kind = "memory"
		header, rangeSize = 32, 36
	case 7:
		d.Kind = "large_memory"
		header, rangeSize = 32, 40
	case 4:
		d.Kind = "interrupt64"
		header, rangeSize = 24, 12
	default:
		return d, errors.New("descriptor type retained raw; decoder unsupported")
	}
	if len(b) < header {
		return d, errors.New("allocation header truncated")
	}
	u := binary.LittleEndian.Uint32
	q := binary.LittleEndian.Uint64
	if u(b) != 0 {
		return d, errors.New("nonzero range count is a requirements list, not an allocation")
	}
	if u(b[4:]) != uint32(rangeSize) {
		return d, errors.New("SDK range element size differs")
	}
	if len(b) != header && len(b) != header+rangeSize {
		return d, fmt.Errorf("allocation size %d differs from header/one-placeholder sizes", len(b))
	}
	d.PlaceholderRange = len(b) > header
	if kind == 4 {
		d.Interrupt = &Interrupt{Number: u(b[12:]), Flags: binary.LittleEndian.Uint16(b[8:]), Group: binary.LittleEndian.Uint16(b[10:]), Affinity: q(b[16:])}
		return d, nil
	}
	base, end := q(b[8:]), q(b[16:])
	if end < base || end-base == ^uint64(0) {
		return d, errors.New("allocation endpoints reversed or full-width size overflows")
	}
	d.Memory = &Memory{Base: base, End: end, Bytes: end - base + 1, Flags: u(b[24:]), Reserved: u(b[28:])}
	return d, nil
}
func validToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Repeat only consecutive IRQ numbers with every other raw byte identical.
// Neither a decoded match alone nor a flag/affinity/tail change can merge.
type Descriptor struct {
	Type        uint32   `json:"type"`
	Bytes       uint32   `json:"bytes"`
	Repeat      uint32   `json:"repeat"`
	Raw         string   `json:"raw_hex"`
	Decoded     *Decoded `json:"decoded,omitempty"`
	DecodeError string   `json:"decode_error,omitempty"`
	Error       string   `json:"error,omitempty"`
}

func appendDescriptor(rows []Descriptor, next Descriptor) []Descriptor {
	next.Repeat = 1
	if len(rows) > 0 && next.Type == 4 && next.Error == "" && next.DecodeError == "" && next.Decoded != nil && next.Decoded.Interrupt != nil {
		last := &rows[len(rows)-1]
		if last.Type == 4 && last.Error == "" && last.DecodeError == "" && last.Decoded != nil && last.Decoded.Interrupt != nil && last.Bytes == next.Bytes && last.Repeat > 0 && last.Repeat < 8192 && uint64(last.Decoded.Interrupt.Number)+uint64(last.Repeat) == uint64(next.Decoded.Interrupt.Number) {
			a, ae := hex.DecodeString(last.Raw)
			b, be := hex.DecodeString(next.Raw)
			if ae == nil && be == nil && len(a) == len(b) && len(a) >= 24 && bytes.Equal(a[:12], b[:12]) && bytes.Equal(a[16:], b[16:]) {
				last.Repeat++
				return rows
			}
		}
	}
	return append(rows, next)
}
