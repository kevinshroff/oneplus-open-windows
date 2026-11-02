// SPDX-License-Identifier: MIT
// Independent wire/ABI validation of the finite charger query capture.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var le = binary.LittleEndian

const captureBytes = 81240
const stateAt = 188
const txAt = 48468
const rxAt = 64852

var stateKeys = []string{"Started", "Complete", "Fault", "Terminal", "OwnTxHead", "OwnRxTail", "Steps", "TraceCount", "TxFrames", "RxFrames", "TxWriteAttempts", "CounterWriteAttempts", "KickAttempts", "RemoteOpenSeen", "OpenSent", "OpenAcked", "IntentsAdvertised", "IgnoredOpens", "QueryIndex", "Pending", "ReplyReceived", "TxCompleted", "CurrentRemoteIntent", "QueriesSentMask", "RepliesMask", "IntentRequestPending", "Unsolicited", "Closing", "CloseSent", "CloseAcked", "RemoteClosed", "RemoteCloseAckSent", "CloseQuietSteps"}
var batteryKeys = []string{"WireValidMask", "ValueValidMask", "ServiceRejectedMask", "PowerUnit", "DesignCapacity", "LastFullCapacity", "DesignVoltage", "CycleCount", "BatteryId", "BatteryState", "RemainingCapacity", "Rate", "Voltage", "PowerState", "ChargingSource", "TemperatureRaw", "CurrentRaw", "OpenCircuitVoltage", "VoltageNow", "CurrentNow", "TemperatureProperty", "CapacityProperty", "UsbOnline", "UsbType", "LegacyStatus"}
var queries = [10][4]uint32{{9, 0, 16, 736}, {1, 0, 16, 44}, {0x30, 6, 24, 24}, {0, 0, 16, 16}, {0x30, 7, 24, 24}, {0x30, 9, 24, 24}, {0x30, 12, 24, 24}, {0x30, 4, 24, 24}, {0x32, 0, 24, 24}, {0x32, 6, 24, 24}}

func decodeStatus(b []byte) (map[string]any, error) {
	if len(b) != 80 || le.Uint32(b) != 80 || le.Uint32(b[4:]) != 1 || string(b[8:16]) != "OG159GL1" {
		return nil, errors.New("G159 status ABI")
	}
	v := map[string]any{}
	for i, n := range []string{"kernel_build", "processors", "IRQL", "firmware_bytes", "firmware_match", "firmware_status", "map_calls", "attempts", "ready", "fault"} {
		v[n] = le.Uint32(b[16+4*i:])
	}
	for i, n := range []string{"interrupt_time", "frequency", "sequence"} {
		v[n] = le.Uint64(b[56+8*i:])
	}
	return v, nil
}
func queryBytes(index int) []byte {
	q := queries[index]
	b := make([]byte, q[2])
	le.PutUint32(b, 0x800a)
	le.PutUint32(b[4:], 1)
	le.PutUint32(b[8:], q[0])
	if q[2] == 24 {
		le.PutUint32(b[16:], q[1])
	}
	return b
}

// Returns the same 35 raw words as the C codec, reconstructed independently.
func decodeReply(index int, b []byte, out *[35]uint32) error {
	q := queries[index]
	if len(b) != int(q[3]) {
		return errors.New("reply size")
	}
	u := func(at int) uint32 { return le.Uint32(b[at:]) }
	if u(0) != 0x800a || u(4) != 1 || u(8) != q[0] || out[0]&(1<<index) != 0 {
		return errors.New("reply envelope/duplicate")
	}
	bit := uint32(1 << index)
	if q[2] == 24 {
		if u(12) != q[1] {
			return errors.New("reply property")
		}
		out[25+index] = u(20)
		if u(20) != 0 {
			out[0] |= bit
			out[2] |= bit
			return nil
		}
		field := map[int]int{2: 17, 4: 18, 5: 19, 6: 20, 7: 21, 8: 22, 9: 23}[index]
		out[field] = u(16)
	} else if index == 0 {
		if u(732) != 0 {
			return errors.New("reply battery id")
		}
		for i, at := range []int{12, 16, 20, 28, 40, 732} {
			out[3+i] = u(at)
		}
		if out[3] > 1 {
			out[0] |= bit
			return nil
		}
	} else if index == 1 {
		for i := 0; i < 8; i++ {
			out[9+i] = u(12 + i*4)
		}
	} else if index == 3 {
		out[24] = u(12)
	} else {
		return errors.New("reply query")
	}
	out[0] |= bit
	out[1] |= bit
	return nil
}
func ring(b []byte, at, n uint32) []byte {
	out := make([]byte, n)
	for i := uint32(0); i < n; i++ {
		out[i] = b[(at+i)&16383]
	}
	return out
}
func validTx(b []byte) bool {
	if len(b) < 8 || len(b) > 2048 || len(b)&7 != 0 {
		return false
	}
	cmd, cid, p := le.Uint16(b), le.Uint16(b[2:]), le.Uint32(b[4:])
	n := len(b)
	switch cmd {
	case 2:
		return cid == 1 && p == 19 && n == 32 && bytes.Equal(b[8:27], []byte("PMIC_RTR_ADSP_APPS\x00")) && bytes.Equal(b[27:], make([]byte, 5))
	case 4, 11:
		return cid == 8 && p == 0 && n == 8
	case 3:
		return cid == 1 && p == 0 && n == 8
	case 6:
		return cid == 1 && p >= 1 && p <= 32 && n == 8
	case 7:
		return cid == 1 && (p == 16 || p == 24) && n == 8
	case 8:
		return cid == 1 && p <= 1 && n == 8
	case 5:
		if cid != 1 || p == 0 || p > 32 || n != 8+8*int(p) {
			return false
		}
		seen := map[uint32]bool{}
		for i := uint32(0); i < p; i++ {
			id := le.Uint32(b[12+8*i:])
			if le.Uint32(b[8+8*i:]) != 1024 || id < 1 || id > 32 || seen[id] {
				return false
			}
			seen[id] = true
		}
		return true
	case 9:
		if cid != 1 || n < 32 || le.Uint32(b[12:]) != 0 {
			return false
		}
		for i := range queries {
			q := queryBytes(i)
			if n == 16+len(q) && le.Uint32(b[8:]) == uint32(len(q)) && bytes.Equal(b[16:], q) {
				return true
			}
		}
	}
	return false
}
func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes {
		return nil, errors.New("G159 capture size")
	}
	status, e := decodeStatus(b[:80])
	if e != nil {
		return nil, e
	}
	if nonce == 0 || le.Uint64(b[80:]) != nonce {
		return nil, errors.New("G159 capture nonce")
	}
	u := func(at int) uint32 { return le.Uint32(b[at:]) }
	begin, end := le.Uint64(b[88:]), le.Uint64(b[96:])
	code, maps := u(104), u(108)
	if end < begin || maps > 4 || u(112) > 1 || u(116) > 1 || u(120) > 1 || u(124) > 1 || u(128) > 1 || u(132) != 0 || u(81236) != 0 {
		return nil, errors.New("G159 capture counters/reserved")
	}
	s := map[string]uint32{}
	for i, n := range stateKeys {
		s[n] = u(stateAt + 4*i)
	}
	for _, n := range []string{"Started", "Complete", "Terminal", "RemoteOpenSeen", "OpenSent", "OpenAcked", "Pending", "ReplyReceived", "TxCompleted", "Closing", "CloseSent", "CloseAcked", "RemoteClosed", "RemoteCloseAckSent"} {
		if s[n] > 1 {
			return nil, fmt.Errorf("state boolean %s", n)
		}
	}
	if s["Fault"] > 12 || s["Steps"] > 2000 || s["TraceCount"] > 128 || s["TxFrames"] > 96 || s["RxFrames"] > 96 || s["QueryIndex"] > 10 || s["CurrentRemoteIntent"] >= 32 || s["QueriesSentMask"] > 1023 || s["RepliesMask"] > 1023 || s["IntentsAdvertised"] > 32 {
		return nil, errors.New("state bounds")
	}
	for _, n := range []string{"OwnTxHead", "OwnRxTail"} {
		if s[n] >= 16384 || s[n]&7 != 0 {
			return nil, errors.New("state ring index")
		}
	}
	initial, final, last := make([]uint32, 8), make([]uint32, 8), make([]uint32, 8)
	for i := 0; i < 8; i++ {
		initial[i] = u(48404 + 4*i)
		final[i] = u(48436 + 4*i)
		last[i] = u(stateAt + 132 + 4*i)
	}
	var computed [35]uint32
	battery := map[string]uint32{}
	replies := []map[string]any{}
	for i, n := range batteryKeys {
		battery[n] = u(stateAt + 164 + 4*i)
	}
	for i, q := range queries {
		n := u(stateAt + 33840 + 4*i)
		if n > 1024 {
			return nil, errors.New("reply storage bounds")
		}
		raw := b[stateAt+33880+i*1024 : stateAt+33880+i*1024+int(n)]
		if s["RepliesMask"]&(1<<i) != 0 {
			if e = decodeReply(i, raw, &computed); e != nil {
				return nil, fmt.Errorf("query %d: %w", i, e)
			}
		}
		if n != 0 {
			replies = append(replies, map[string]any{"query": i, "opcode": q[0], "property": q[1], "bytes": n, "hex": hex.EncodeToString(raw)})
		}
	}
	for i, want := range computed {
		if u(stateAt+164+4*i) != want {
			return nil, fmt.Errorf("independent battery word %d", i)
		}
	}
	if computed[0] != s["RepliesMask"] {
		return nil, errors.New("reply masks")
	}
	trace := []map[string]uint32{}
	var txCount, rxCount, queryCount, txBytes, rxBytes uint32
	txCursor, rxCursor := uint32(16), uint32(16)
	// Bind retained reply bytes to the independent RX fragment reconstruction.
	assembled := map[uint32][]byte{}
	wireReplies := map[int][]byte{}
	for i := uint32(0); i < s["TraceCount"]; i++ {
		at := stateAt + 44120 + 32*int(i)
		v := map[string]uint32{}
		for j, n := range []string{"direction", "command", "channel", "parameter", "bytes", "TX_head", "RX_tail", "query"} {
			v[n] = u(at + 4*j)
		}
		dir, n := v["direction"], v["bytes"]
		if dir < 1 || dir > 2 || n < 8 || n > 2048 || n&7 != 0 || v["TX_head"] >= 16384 || v["RX_tail"] >= 16384 || (v["TX_head"]|v["RX_tail"])&7 != 0 || v["query"] > 10 {
			return nil, errors.New("trace bounds")
		}
		endIndex := v["TX_head"]
		base := txAt
		if dir == 2 {
			endIndex = v["RX_tail"]
			base = rxAt
		}
		frame := ring(b[base:base+16384], (endIndex-n)&16383, n)
		if code == 0 {
			if uint32(le.Uint16(frame)) != v["command"] || uint32(le.Uint16(frame[2:])) != v["channel"] || le.Uint32(frame[4:]) != v["parameter"] {
				return nil, errors.New("trace/wire header")
			}
			if dir == 1 {
				txCursor = (txCursor + n) & 16383
				txBytes += n
				if txCursor != endIndex || !validTx(frame) {
					return nil, errors.New("TX whitelist/cursor")
				}
				if v["command"] == 9 {
					if queryCount >= 10 || v["query"] != queryCount || !bytes.Equal(frame[16:], queryBytes(int(queryCount))) {
						return nil, errors.New("TX fixed batch order")
					}
					queryCount++
				}
			} else {
				rxCursor = (rxCursor + n) & 16383
				rxBytes += n
				if rxCursor != endIndex {
					return nil, errors.New("RX cursor")
				}
				if v["command"] == 9 || v["command"] == 12 {
					if n < 16 || v["channel"] != 8 {
						return nil, errors.New("RX data channel")
					}
					iid := v["parameter"]
					chunk, left := le.Uint32(frame[8:]), le.Uint32(frame[12:])
					if iid < 1 || iid > 32 || chunk > 1024 || left > 1024 || n != ((16+chunk+7)&^7) || uint32(len(assembled[iid]))+chunk+left > 1024 {
						return nil, errors.New("RX fragment bounds")
					}
					if v["command"] == 9 {
						if len(assembled[iid]) != 0 {
							return nil, errors.New("RX fragment start")
						}
					} else if len(assembled[iid]) == 0 {
						return nil, errors.New("RX fragment continuation")
					}
					assembled[iid] = append(assembled[iid], frame[16:16+chunk]...)
					if left == 0 {
						data := assembled[iid]
						if len(data) >= 12 && le.Uint32(data) == 0x800a && le.Uint32(data[4:]) == 1 {
							q := int(v["query"])
							if q >= 10 || wireReplies[q] != nil {
								return nil, errors.New("RX reply order")
							}
							wireReplies[q] = data
						}
						delete(assembled, iid)
					}
				}
			}
		}
		if dir == 1 {
			txCount++
		} else {
			rxCount++
		}
		trace = append(trace, v)
	}
	answered := code == 0
	if answered {
		if maps != 4 || u(112) != 1 || u(116) != 1 || u(120) != 1 || u(124) != 0 || u(128) != 0 || hex.EncodeToString(b[136:168]) != "f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29" {
			return nil, errors.New("successful platform admission")
		}
		for n, want := range map[string]uint32{"kernel_build": 26100, "processors": 8, "IRQL": 0, "firmware_bytes": 576, "firmware_match": 1, "firmware_status": 0, "map_calls": 4, "attempts": 1, "ready": 1, "fault": 0} {
			if status[n] != want {
				return nil, fmt.Errorf("successful status %s", n)
			}
		}
		for n, want := range map[string]uint32{"Started": 1, "Complete": 1, "Fault": 0, "Terminal": 0, "RemoteOpenSeen": 1, "OpenSent": 1, "OpenAcked": 1, "IgnoredOpens": 8, "QueryIndex": 10, "Pending": 0, "QueriesSentMask": 1023, "RepliesMask": 1023, "Closing": 1, "CloseSent": 1, "CloseAcked": 1} {
			if s[n] != want {
				return nil, fmt.Errorf("successful state %s", n)
			}
		}
		if queryCount != 10 || txBytes >= 16384 || rxBytes >= 16384 || txCount != s["TxFrames"] || rxCount != s["RxFrames"] || s["TxWriteAttempts"] != txCount || s["CounterWriteAttempts"] != txCount+rxCount || s["KickAttempts"] != txCount+rxCount || s["TraceCount"] != txCount+rxCount {
			return nil, errors.New("successful operation accounting")
		}
		if initial[0] != 16 || initial[1] != 16 || initial[2] != 16 || initial[3] < 256 || initial[3] >= 16384 || initial[3]&7 != 0 {
			return nil, errors.New("initial handoff counters")
		}
		prefix := ring(b[rxAt:rxAt+16384], 16, 240)
		sum := sha256.Sum256(prefix)
		if hex.EncodeToString(sum[:]) != "1c0f5fda9d4e18f6b925176300f0117c44f14cc660ec388a6bddaec5dca622ed" {
			return nil, errors.New("initial handoff bytes")
		}
		for i := 4; i < 8; i++ {
			if initial[i] != 0 {
				return nil, errors.New("initial reserved words")
			}
		}
		for _, d := range [][]uint32{last, final} {
			for i, n := range d {
				if i < 4 {
					if n >= 16384 || n&7 != 0 {
						return nil, errors.New("final index")
					}
				} else if n != 0 {
					return nil, errors.New("final reserved word")
				}
			}
			if d[0] != s["OwnTxHead"] || d[1] != s["OwnTxHead"] || d[2] != s["OwnRxTail"] || d[3] != s["OwnRxTail"] {
				return nil, errors.New("closed channel consumption")
			}
		}
		for i := range queries {
			n := u(stateAt + 33840 + 4*i)
			if !bytes.Equal(wireReplies[i], b[stateAt+33880+i*1024:stateAt+33880+i*1024+int(n)]) {
				return nil, errors.New("RX reply storage binding")
			}
		}
		for i, size := range []uint32{32, 16384, 16384} {
			off := u(168 + 4*i)
			if off < 32 || off&7 != 0 || off > 0x60000-size {
				return nil, errors.New("slot range")
			}
			for j := 0; j < i; j++ {
				other := u(168 + 4*j)
				os := []uint32{32, 16384, 16384}[j]
				if off < other+os && other < off+size {
					return nil, errors.New("slot overlap")
				}
			}
		}
	} else if s["Complete"] != 0 {
		return nil, errors.New("failed operation marked complete")
	}
	values := map[string]any{"raw": battery, "units": "PowerUnit 0=mWh/mW, 1=mAh/mA for legacy capacity/rate. Legacy Voltage is mV. Properties retain raw integers; temperature and signed current require corroboration."}
	if computed[1]&3 == 3 && computed[5] != 0 {
		values["remaining_over_last_full_percent"] = 100 * float64(computed[10]) / float64(computed[5])
	}
	if computed[1]&(1<<5) != 0 {
		values["current_now_signed_raw"] = int32(computed[19])
	}
	txSum, rxSum := sha256.Sum256(b[txAt:rxAt]), sha256.Sum256(b[rxAt:81236])
	return map[string]any{"code": code, "status": status, "begin_100ns": begin, "end_100ns": end, "duration_ms": float64(end-begin) / 10000, "maps": maps, "cancelled": u(124), "timed_out": u(128), "state": s, "initial_descriptor": initial, "final_descriptor": final, "last_descriptor": last, "trace": trace, "replies": replies, "battery": values, "all_queries_answered": answered, "channel_close_acknowledged": s["CloseAcked"] == 1, "TX_sha256": hex.EncodeToString(txSum[:]), "RX_sha256": hex.EncodeToString(rxSum[:]), "charging_qualified": false}, nil
}
