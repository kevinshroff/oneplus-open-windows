package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type captureState struct {
	Phase            uint32 `json:"phase"`
	Captures         uint32 `json:"captures"`
	Retirements      uint32 `json:"retirements"`
	Slots            uint32 `json:"slots"`
	CurrentNonce     uint64 `json:"current_nonce"`
	LastRetiredNonce uint64 `json:"last_retired_nonce"`
	TotalMaps        uint64 `json:"lifetime_maps"`
	SlotMaps         uint32 `json:"last_slot_maps"`
}

func decodeCaptureState(b []byte) (captureState, error) {
	var s captureState
	if len(b) != 64 || le.Uint32(b) != 64 || le.Uint32(b[4:]) != 1 || string(b[8:16]) != "G137KEY1" || le.Uint32(b[60:]) != 0 {
		return s, fmt.Errorf("G137 state ABI")
	}
	s = captureState{le.Uint32(b[16:]), le.Uint32(b[20:]), le.Uint32(b[24:]), le.Uint32(b[28:]), le.Uint64(b[32:]), le.Uint64(b[40:]), le.Uint64(b[48:]), le.Uint32(b[56:])}
	if s.Phase > 3 || s.Slots != 32 || s.Captures > 32 || s.Retirements > s.Captures || s.SlotMaps > 5 || s.TotalMaps > 160 {
		return s, fmt.Errorf("G137 state bounds")
	}
	if s.Captures == 0 && (s.TotalMaps != 0 || s.SlotMaps != 0) {
		return s, fmt.Errorf("G137 maps before first capture")
	}
	if (s.Captures == 0 && s.CurrentNonce != 0) || (s.Captures != 0 && s.CurrentNonce == 0) || (s.Retirements == 0 && s.LastRetiredNonce != 0) || (s.Retirements != 0 && s.LastRetiredNonce == 0) {
		return s, fmt.Errorf("G137 nonce history")
	}
	if s.Phase == 0 && (s.Captures != s.Retirements || s.TotalMaps != uint64(s.Captures)*5 || (s.Captures != 0 && (s.SlotMaps != 5 || s.CurrentNonce != s.LastRetiredNonce))) {
		return s, fmt.Errorf("G137 empty-slot history")
	}
	if s.Phase == 1 && (s.Captures != s.Retirements+1 || s.SlotMaps != 0 || s.TotalMaps != uint64(s.Retirements)*5) {
		return s, fmt.Errorf("G137 in-flight history")
	}
	if s.Phase == 2 && (s.Captures != s.Retirements+1 || s.SlotMaps != 5 || s.TotalMaps != uint64(s.Captures)*5) {
		return s, fmt.Errorf("G137 ready-slot history")
	}
	return s, nil
}
func keyRequest(nonce uint64, count uint32) []byte {
	q := make([]byte, 32)
	le.PutUint32(q, 32)
	le.PutUint32(q[4:], 1)
	copy(q[8:], "OG99KEY1")
	le.PutUint64(q[16:], nonce)
	le.PutUint32(q[24:], count)
	return q
}
func retireRequest(nonce uint64, b []byte) ([]byte, error) {
	v, e := decodeCapture(b, nonce)
	if e != nil {
		return nil, e
	}
	if v["operation_code"] != uint32(0) {
		return nil, fmt.Errorf("failed/uncertain capture is retained until reboot")
	}
	q := make([]byte, 32+captureBytes)
	copy(q, keyRequest(nonce, 0))
	copy(q[32:], b)
	return q, nil
}
func boundedCapture(f *os.File) ([]byte, error) {
	stat, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !stat.Mode().IsRegular() || stat.Size() != captureBytes {
		return nil, fmt.Errorf("exact regular capture file required")
	}
	b := make([]byte, captureBytes)
	if _, e = io.ReadFull(f, b); e != nil {
		return nil, e
	}
	var extra [1]byte
	n, e := f.Read(extra[:])
	if n != 0 || e != io.EOF {
		return nil, fmt.Errorf("capture changed length")
	}
	return b, nil
}
func durableCapture(path string, nonce uint64) ([]byte, string, error) {
	// Flush the existing file, close, reopen and compare bounded bytes before ACK.
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return nil, "", e
	}
	b, e := boundedCapture(f)
	if e == nil {
		_, e = retireRequest(nonce, b)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil {
		return nil, "", e
	}
	if closed != nil {
		return nil, "", closed
	}
	f, e = os.Open(path)
	if e != nil {
		return nil, "", e
	}
	again, e := boundedCapture(f)
	closed = f.Close()
	if e != nil {
		return nil, "", e
	}
	if closed != nil {
		return nil, "", closed
	}
	if !bytes.Equal(b, again) {
		return nil, "", fmt.Errorf("persisted capture differs after reopen")
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}
func validateRetirement(before, after captureState, nonce uint64) error {
	if nonce == 0 || before.CurrentNonce != nonce || (before.Phase != 2 && !(before.Phase == 0 && before.LastRetiredNonce == nonce)) {
		return fmt.Errorf("capture is not awaiting this acknowledgment")
	}
	if after.Phase != 0 || after.Captures != before.Captures || after.Retirements != before.Captures || after.CurrentNonce != nonce || after.LastRetiredNonce != nonce || after.TotalMaps != before.TotalMaps || after.SlotMaps != 5 {
		return fmt.Errorf("retirement response does not match requested capture")
	}
	return nil
}
