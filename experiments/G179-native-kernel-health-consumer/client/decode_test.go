package main

import (
	"encoding/binary"
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/success.bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestActualCRequest(t *testing.T) {
	b, e := os.ReadFile("testdata/read-request.bin")
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != string(encodeRequest(0x1234)) {
		t.Fatal("actual C request mismatch")
	}
}
func TestActualCProviderFixture(t *testing.T) {
	b := fixture(t)
	n := u64(b, at(abi.Capture, "Nonce"))
	v, e := decodeCapture(b, n)
	if e != nil {
		t.Fatal(e)
	}
	if v["valid_at_acquisition"] != true || v["fresh_at_snapshot"] != true {
		t.Fatal(v)
	}
	h := v["health"].(map[string]any)
	if h["FloatMv"] != uint32(4470) || h["FastMa"] != uint32(300) {
		t.Fatal(h)
	}
}
func TestHistoricalAcquisitionIsNotRefreshed(t *testing.T) {
	b := fixture(t)
	n := u64(b, at(abi.Capture, "Nonce"))
	at := at(abi.Status, "InterruptTime")
	binary.LittleEndian.PutUint64(b[at:], u64(b, at)+60000000)
	v, e := decodeCapture(b, n)
	if e != nil {
		t.Fatal(e)
	}
	if v["valid_at_acquisition"] != true || v["fresh_at_snapshot"] != false {
		t.Fatal("historical values relabeled fresh", v)
	}
}
func TestNoUnmeasuredValues(t *testing.T) {
	b := fixture(t)
	n := u64(b, at(abi.Capture, "Nonce"))
	r := at(abi.Capture, "Result")
	for i := r; i < len(b); i++ {
		b[i] = 0
	}
	binary.LittleEndian.PutUint32(b[at(abi.Capture, "Admission"):], 1001)
	binary.LittleEndian.PutUint32(b[at(abi.Status, "Fault"):], 1)
	v, e := decodeCapture(b, n)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := v["health"]; ok {
		t.Fatal("unmeasured physical values exposed")
	}
	b[r+at(abi.IO, "Health")] = 1
	if _, e = decodeCapture(b, n); e == nil {
		t.Fatal("invalid acquisition exposes values")
	}
}
func TestCorruption(t *testing.T) {
	original := fixture(t)
	n := u64(original, at(abi.Capture, "Nonce"))
	r := at(abi.Capture, "Result")
	h := r + at(abi.IO, "Health")
	checks := []struct {
		name  string
		off   int
		value uint32
	}{{"status size", 0, 1}, {"status version", 4, 2}, {"magic", 8, 0}, {"nonce", at(abi.Capture, "Nonce"), 0}, {"capture reserved", at(abi.Capture, "Reserved"), 1}, {"header map", at(abi.Status, "MapCalls"), 1}, {"header safe", at(abi.Status, "SafeToUnload"), 0}, {"header fault", at(abi.Status, "Fault"), 1}, {"header bool", at(abi.Status, "Ready"), 2}, {"admission", at(abi.Capture, "Admission"), 1}, {"created", r + at(abi.IO, "CreatedMask"), 0}, {"open", r + at(abi.IO, "OpenedMask"), 0}, {"send", r + at(abi.IO, "SentMask"), 0}, {"receive", r + at(abi.IO, "ReceivedMask"), 0}, {"close", r + at(abi.IO, "ClosedMask"), 0}, {"delete", r + at(abi.IO, "DeletedMask"), 0}, {"buffers", r + at(abi.IO, "ManagedBuffers"), 3}, {"stage", r + at(abi.IO, "Stage"), 30}, {"failure", r + at(abi.IO, "FailedStage"), 1}, {"validation", r + at(abi.IO, "ValidationAttempted"), 0}, {"healthcode", r + at(abi.IO, "HealthCode"), 1}, {"result status", r + at(abi.IO, "LastStatus"), 1}, {"provider status", r + at(abi.IO, "SendStatus"), 1}, {"result length", r + at(abi.IO, "ReceivedBytes"), 0}, {"reserved", r + at(abi.IO, "Reserved"), 1}, {"physical nonce", h + at(abi.Health, "Nonce"), 0}, {"FV", h + at(abi.Health, "FloatMv"), 4550}, {"FCC", h + at(abi.Health, "FastMa"), 400}, {"enable", h + at(abi.Health, "Enable"), 2}, {"USB", h + at(abi.Health, "UsbType"), 1}, {"state", h + at(abi.Health, "StateLast"), 8}, {"voltage", h + at(abi.Health, "VoltageMv"), 9999}, {"temp", h + at(abi.Health, "TemperatureDeciK"), 4000}, {"current", h + at(abi.Health, "CurrentRaw"), 501}, {"percent", h + at(abi.Health, "ChargePercent"), 101}, {"capacity", h + at(abi.Health, "FullMah"), 0}}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			b := append([]byte(nil), original...)
			binary.LittleEndian.PutUint32(b[c.off:], c.value)
			if _, e := decodeCapture(b, n); e == nil {
				t.Fatal("corruption accepted", c.name)
			}
		})
	}
	for _, length := range []int{0, 96, len(original) - 1, len(original) + 1} {
		b := make([]byte, length)
		copy(b, original)
		if _, e := decodeCapture(b, n); e == nil {
			t.Fatal("length accepted", length)
		}
	}
}
