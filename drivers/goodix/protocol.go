// SPDX-License-Identifier: GPL-2.0-only
// Protocol observations: OnePlusOSS commit 46cfd06fc4c0e12dbe294badb924a533f1d9fb06.
// See provenance.txt for source functions and limits of this offline implementation.
package goodix

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HeaderBytes    = 8
	PointBytes     = 8
	MaxContacts    = 10
	MaxReportBytes = HeaderBytes + PointBytes*MaxContacts + 2
)

var (
	ErrNotTouch = errors.New("not a touch snapshot")
	ErrStylus   = errors.New("stylus report requires a separate decoder")
)

type Contact struct {
	ID           uint8
	X, Y         uint16
	Major, Minor uint8
}

// Snapshot contains raw controller coordinates. An empty valid snapshot releases
// contacts; an error must not be converted to a synthetic all-contacts-up event.
type Snapshot struct{ Contacts []Contact }

func validChecksum(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	var sum uint16
	for _, v := range b[:len(b)-2] {
		sum += uint16(v)
	}
	return sum == binary.LittleEndian.Uint16(b[len(b)-2:])
}

// Decode accepts an assembled finger report, possibly with the source driver's
// trailing pre-read bytes. It deliberately rejects corrupt payload checksums:
// the reference caller tests ret<0 although checksum_cmp returns 1 on mismatch.
func Decode(b []byte) (Snapshot, error) {
	bad := func(s string) (Snapshot, error) { return Snapshot{}, fmt.Errorf("Goodix report: %s", s) }
	if len(b) < HeaderBytes || len(b) > MaxReportBytes {
		return bad("length")
	}
	if !validChecksum(b[:HeaderBytes]) {
		return bad("header checksum")
	}
	if b[0]&0x80 == 0 {
		return Snapshot{}, ErrNotTouch
	}
	n := int(b[2] & 15)
	if n > MaxContacts {
		return bad("contact count")
	}
	need := HeaderBytes + n*PointBytes + 2
	if len(b) < need {
		return bad("truncated points")
	}
	if n > 0 && (b[HeaderBytes]&15 == 1 || b[HeaderBytes]&15 == 3) {
		return Snapshot{}, ErrStylus
	}
	if !validChecksum(b[HeaderBytes:need]) {
		return bad("point checksum")
	}
	out := Snapshot{Contacts: make([]Contact, 0, n)}
	var seen uint16
	for i := 0; i < n; i++ {
		p := b[HeaderBytes+i*PointBytes : HeaderBytes+(i+1)*PointBytes]
		id := p[0] >> 4
		if id >= MaxContacts || seen&(1<<id) != 0 {
			return bad("invalid or duplicate contact ID")
		}
		seen |= 1 << id
		major, minor := p[6], p[7]
		if major < minor {
			major, minor = minor, major
		}
		out.Contacts = append(out.Contacts, Contact{id, binary.LittleEndian.Uint16(p[2:4]), binary.LittleEndian.Uint16(p[4:6]), major, minor})
	}
	return out, nil
}

// ReadRequest describes one full-duplex SPI transfer with chip-select held.
// Receive payload begins at byte 8. Payload clocks transmit zero, matching the
// zero-initialized source buffers; address bytes are big endian.
func ReadRequest(address uint32, n int) ([]byte, error) {
	if n < 1 || n > MaxReportBytes {
		return nil, errors.New("read size outside report bounds")
	}
	b := make([]byte, 8+n)
	b[0] = 0xf1
	binary.BigEndian.PutUint32(b[1:5], address)
	b[5], b[6], b[7] = 0xff, 0xff, 0xff
	return b, nil
}

// WriteRequest is framing only. Nothing in this package opens or writes a bus.
func WriteRequest(address uint32, payload []byte) ([]byte, error) {
	if len(payload) < 1 || len(payload) > MaxReportBytes {
		return nil, errors.New("write size outside report bounds")
	}
	b := make([]byte, 5+len(payload))
	b[0] = 0xf0
	binary.BigEndian.PutUint32(b[1:5], address)
	copy(b[5:], payload)
	return b, nil
}
