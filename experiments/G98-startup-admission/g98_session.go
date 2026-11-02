// SPDX-License-Identifier: MIT
// Portable decoder for the fixed source-owned session status.
package main

import (
	"encoding/binary"
	"errors"
)

func decodeSession(b []byte) (map[string]any, error) {
	if len(b) != 96 || binary.LittleEndian.Uint32(b) != 96 || binary.LittleEndian.Uint32(b[4:]) != 1 || string(b[8:16]) != "OPG98HD1" {
		return nil, errors.New("G98 session ABI differs")
	}
	names := []string{"state", "stop_reason", "starts", "hardware_calls", "result_ready", "outcome", "stop_checks", "stop_seen", "inhibit", "thread_joined", "phase", "poll_cycles"}
	v := map[string]any{}
	for i, n := range names {
		v[n] = binary.LittleEndian.Uint32(b[16+i*4:])
	}
	for i, n := range []string{"begin_us", "end_us", "stop_us"} {
		v[n] = binary.LittleEndian.Uint64(b[64+i*8:])
	}
	v["thread_create_status"] = binary.LittleEndian.Uint32(b[88:])
	v["stop_requests"] = binary.LittleEndian.Uint32(b[92:])
	u := func(n string) uint32 { return v[n].(uint32) }
	if u("state") > 3 || u("stop_reason") > 6 || u("starts") > 1 || u("hardware_calls") > 4 || u("result_ready") > 1 || u("outcome") > 4 || u("inhibit") > 1 || u("thread_joined") > 1 || u("poll_cycles") > 300000 {
		return nil, errors.New("G98 session bounds differ")
	}
	if u("state") == 0 && (u("starts") != 0 || u("hardware_calls") != 0 || u("result_ready") != 0) {
		return nil, errors.New("idle session already consumed")
	}
	if u("state") != 0 && u("starts") != 1 {
		return nil, errors.New("session start count differs")
	}
	if u("thread_joined") != 0 && u("state") != 3 {
		return nil, errors.New("running session claims joined thread")
	}
	if u("outcome") == 1 || u("outcome") == 2 || u("outcome") == 4 {
		if u("state") != 3 || u("result_ready") != 1 {
			return nil, errors.New("terminal outcome without frozen result")
		}
	}
	return v, nil
}

func decodeRuntime(b []byte) (map[string]any,error) {
 if len(b)!=160||binary.LittleEndian.Uint32(b)!=160||binary.LittleEndian.Uint32(b[4:])!=1||string(b[8:16])!="OPG98HD1" {return nil,errors.New("G98 runtime ABI differs")}
 v:=map[string]any{}
 for i,n:=range []string{"state","stop_reason","starts","hardware_calls","result_ready","outcome","inhibit","thread_joined"} {v[n]=binary.LittleEndian.Uint32(b[16+i*4:])}
 for i,n:=range []string{"cycles","epochs","reports_submitted","reports_accepted","completed_epoch_reads","completed_epoch_writes","completed_epoch_wires","begin_us","last_cycle_us","owner_starts","recoveries"} {v[n]=binary.LittleEndian.Uint64(b[48+i*8:])}
 for i,n:=range []string{"hardware_code","poll_code","touch_code","D0","started","fault_ready"} {v[n]=binary.LittleEndian.Uint32(b[136+i*4:])}
 if v["state"].(uint32)>3||v["stop_reason"].(uint32)>6||v["starts"].(uint32)>1||v["hardware_calls"].(uint32)>4||v["result_ready"].(uint32)>1||v["outcome"].(uint32)>4||v["D0"].(uint32)>1||v["started"].(uint32)>1||v["fault_ready"].(uint32)>1 {return nil,errors.New("G98 runtime bounds differ")}
 return v,nil
}

func decodeFault(b []byte) (map[string]any,error) {
 if len(b)!=136||binary.LittleEndian.Uint32(b)!=136||binary.LittleEndian.Uint32(b[4:])!=1||string(b[8:16])!="OPG98HD1" {return nil,errors.New("G98 fault ABI differs")}
 u:=func(at int)uint32{return binary.LittleEndian.Uint32(b[at:])}
 if u(16)>1||u(28)>90{return nil,errors.New("G98 fault bounds differ")}
 raw:=make([]uint32,u(28));for i:=range raw {raw[i]=uint32(b[40+i])};return map[string]any{"present":u(16),"poll_code":u(20),"frame_error":u(24),"read_bytes":u(28),"at_us":binary.LittleEndian.Uint64(b[32:]),"raw_bytes":raw},nil
}
