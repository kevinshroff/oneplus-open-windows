package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var le = binary.LittleEndian
const captureBytes = 34152

func decodeStatus(b []byte) (map[string]any, error) {
	if len(b) != 80 || le.Uint32(b) != 80 || le.Uint32(b[4:]) != 1 || string(b[8:16]) != "OG158GL1" {
		return nil, errors.New("G158 status ABI")
	}
	v := map[string]any{}
	for i, n := range []string{"kernel_build", "processors", "IRQL", "firmware_bytes", "firmware_match", "firmware_status", "map_calls", "attempts", "ready", "fault"} {
		v[n] = le.Uint32(b[16+4*i:])
	}
	for i, n := range []string{"interrupt_time", "frequency", "sequence"} { v[n] = le.Uint64(b[56+8*i:]) }
	return v, nil
}

func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes { return nil, errors.New("G158 capture size") }
	status, err := decodeStatus(b[:80]); if err != nil { return nil, err }
	if nonce == 0 || le.Uint64(b[80:]) != nonce { return nil, errors.New("G158 nonce") }
	u := func(at int) uint32 { return le.Uint32(b[at:]) }
	begin, end := le.Uint64(b[88:]), le.Uint64(b[96:])
	code, maps, fdt, toc, slots := u(104), u(108), u(112), u(116), u(120)
	if end < begin || maps > 4 || fdt > 1 || toc > 1 || slots > 1 || u(124) > 1 || u(128) > 1 || u(132) != 0 || u(34148) != 0 {
		return nil, errors.New("G158 capture counters/reserved")
	}
	state := map[string]uint32{}
	keys := []string{"Started", "Complete", "Fault", "OwnTxHead", "OwnRxTail", "LocalVersionSent", "PeerVersionSeen", "PeerVersionAckSent", "LocalAckObserved", "TxFrames", "RxFrames", "TxWriteAttempts", "CounterWriteAttempts", "KickAttempts", "Steps", "TraceCount", "NextCommand", "NextCommandPresent"}
	for i, key := range keys { state[key] = u(188 + 4*i) }
	for _, key := range []string{"Started", "Complete", "LocalVersionSent", "PeerVersionSeen", "PeerVersionAckSent", "LocalAckObserved", "NextCommandPresent"} {
		if state[key] > 1 { return nil, fmt.Errorf("G158 boolean %s", key) }
	}
	if state["Fault"] > 7 || state["TxFrames"] > 16 || state["RxFrames"] > 16 || state["TraceCount"] > 32 || state["Steps"] > 600 || state["OwnTxHead"] >= 16384 || state["OwnRxTail"] >= 16384 || (state["OwnTxHead"]|state["OwnRxTail"])&7 != 0 {
		return nil, errors.New("G158 state bounds")
	}
	trace := []map[string]uint32{}
	for i := uint32(0); i < state["TraceCount"]; i++ {
		at := 292 + 32*int(i)
		e := map[string]uint32{}
		for j, key := range []string{"direction", "command", "version", "features", "TX_head", "RX_tail", "TX_tail", "RX_head"} { e[key] = u(at + 4*j) }
		if e["direction"] < 1 || e["direction"] > 2 || e["command"] > 1 || e["version"] != 1 || (e["features"] != 0 && (e["direction"] != 2 || e["command"] != 0 || e["features"] != 7)) {
			return nil, errors.New("G158 trace frame")
		}
		for _, key := range []string{"TX_head", "RX_tail", "TX_tail", "RX_head"} { if e[key] >= 16384 || e[key]&7 != 0 { return nil, errors.New("G158 trace index") } }
		trace = append(trace, e)
	}
	initial, final, last := make([]uint32, 8), make([]uint32, 8), make([]uint32, 8)
	for i := 0; i < 8; i++ { initial[i] = u(1316+4*i); final[i] = u(1348+4*i); last[i] = u(260+4*i) }
	negotiated := code == 0
	if negotiated {
		if maps != 4 || fdt != 1 || toc != 1 || slots != 1 || u(124) != 0 || u(128) != 0 || hex.EncodeToString(b[136:168]) != "f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29" {
			return nil, errors.New("G158 successful platform admission")
		}
		for key, want := range map[string]uint32{"kernel_build":26100,"processors":8,"IRQL":0,"firmware_bytes":576,"firmware_match":1,"firmware_status":0,"map_calls":4,"attempts":1,"ready":1,"fault":0} {
			if status[key] != want { return nil, fmt.Errorf("G158 successful status %s", key) }
		}
		for key, want := range map[string]uint32{"Started":1,"Complete":1,"Fault":0,"LocalVersionSent":1,"PeerVersionSeen":1,"PeerVersionAckSent":1,"LocalAckObserved":1} {
			if state[key] != want { return nil, fmt.Errorf("G158 successful state %s", key) }
		}
		if state["TxFrames"] < 2 || state["RxFrames"] < 2 || state["TxWriteAttempts"] != state["TxFrames"] || state["CounterWriteAttempts"] != state["TxFrames"]+state["RxFrames"] || state["KickAttempts"] != state["RxFrames"] || state["TraceCount"] != state["TxFrames"]+state["RxFrames"] {
			return nil, errors.New("G158 successful write/trace accounting")
		}
		var txCount, rxCount, rxAck, txVersion, txAck uint32
		for _, event := range trace {
			if event["direction"] == 1 {
				at := 1380 + int(txCount)*8
				if uint32(le.Uint16(b[at:])) != event["command"] || le.Uint16(b[at+2:]) != 1 || le.Uint32(b[at+4:]) != 0 { return nil, errors.New("G158 TX trace/wire binding") }
				txCount++; if event["command"] == 0 { txVersion++ } else { txAck++ }
			} else { rxCount++; if event["command"] == 1 { rxAck++ } }
		}
		if txCount != state["TxFrames"] || rxCount != state["RxFrames"] || rxAck == 0 || txVersion != 1 || txAck == 0 || len(trace) < 3 || trace[0]["direction"] != 1 || trace[0]["command"] != 0 || trace[1]["direction"] != 1 || trace[1]["command"] != 1 || trace[2]["direction"] != 2 || trace[2]["command"] != 0 || trace[2]["features"] != 7 {
			return nil, errors.New("G158 successful negotiation trace")
		}
		for i, want := range []uint32{0,0,0,8,0,0,0,0} { if initial[i] != want { return nil, errors.New("G158 successful initial state") } }
		for _, d := range [][]uint32{last, final} {
			for i, value := range d { if i < 4 { if value >= 16384 || value&7 != 0 { return nil, errors.New("G158 final indices") } } else if value != 0 { return nil, errors.New("G158 final reserved words") } }
			if d[0] != state["OwnTxHead"] || d[1] != state["OwnTxHead"] || d[2] != state["OwnRxTail"] { return nil, errors.New("G158 final host ownership/peer consumption") }
		}
		for i, size := range []uint32{32,16384,16384} {
			offset := u(168 + 4*i)
			if offset < 32 || offset&7 != 0 || offset > 0x60000-size { return nil, errors.New("G158 slot bounds") }
			for j := 0; j < i; j++ { other := u(168+4*j); otherSize := []uint32{32,16384,16384}[j]; if offset < other+otherSize && other < offset+size { return nil, errors.New("G158 overlapping slots") } }
		}
		if u(180) < 3 || u(180) > 256 || u(184) > 0x60000 { return nil, errors.New("G158 slot inventory") }
	} else if state["Complete"] != 0 { return nil, errors.New("G158 failed operation marked complete") }
	pending := (final[3] - final[2]) & 16383
	preview := []byte{}
	if slots != 0 && final[2] < 16384 && final[3] < 16384 {
		n := pending; if n > 128 { n = 128 }
		for i := uint32(0); i < n; i++ { preview = append(preview, b[17764+int((final[2]+i)&16383)]) }
	}
	if negotiated && state["NextCommandPresent"] != 0 && (len(preview) < 8 || uint32(le.Uint16(preview)) != state["NextCommand"]) { return nil, errors.New("G158 preserved next frame") }
	txHash, rxHash := sha256.Sum256(b[1380:17764]), sha256.Sum256(b[17764:34148])
	return map[string]any{"code":code,"status":status,"begin_100ns":begin,"end_100ns":end,"maps":maps,"FDT_match":fdt,"TOC_match":toc,"slots_match":slots,"state":state,"trace":trace,"initial_descriptor":initial,"final_descriptor":final,"last_descriptor":last,"version_round_trip_observed":negotiated,"RX_pending_bytes":pending,"RX_pending_preview_hex":hex.EncodeToString(preview),"TX_sha256":hex.EncodeToString(txHash[:]),"RX_sha256":hex.EncodeToString(rxHash[:]),"channel_open_requests":0,"charger_requests":0,"charging_qualified":false},nil
}
