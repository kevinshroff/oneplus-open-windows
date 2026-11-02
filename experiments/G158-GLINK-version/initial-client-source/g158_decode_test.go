package main

import (
	"fmt"
	"os"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper(); b,err:=os.ReadFile("testdata/"+name); if err!=nil {t.Fatal(err)}; return b
}
func TestActualCProducer(t *testing.T) {
	for _,name:=range []string{"success-open.bin","refused-FDT.bin","timeout-after-write.bin"} {
		t.Run(name,func(t *testing.T){b:=fixture(t,name);v,err:=decodeCapture(b,0x1234);if err!=nil{t.Fatal(err)}
			if v["version_round_trip_observed"]!=(name=="success-open.bin") {t.Fatal("incorrect classification")}
			if v["charging_qualified"]!=false||v["charger_requests"]!=0||v["channel_open_requests"]!=0{t.Fatal("scope")}
		})
	}
}
func TestRefuseSuccessfulCaptureCorruption(t *testing.T) {
	tests:=[]struct{name string;offset int;value uint32}{
		{"size",0,79},{"ABI",4,2},{"magic",8,0},{"nonce",80,123},
		{"map-limit",108,5},{"FDT-not-admitted",112,0},{"TOC-not-admitted",116,0},{"slots-not-admitted",120,0},
		{"canceled",124,1},{"timeout",128,1},{"reserved",132,1},{"FDT-digest",136,0},
		{"slot-overflow",168,0xffffff00},{"slot-alignment",172,97},{"slot-overlap",176,96},
		{"item-count",180,0},{"heap-bound",184,0xffffffff},
		{"not-started",188,0},{"not-complete",192,0},{"fault",196,1},
		{"invalid-own-head",200,16384},{"unaligned-own-tail",204,9},
		{"no-local-version",208,0},{"no-peer-version",212,0},{"no-peer-ACK-sent",216,0},{"no-local-ACK",220,0},
		{"TX-frames",224,0},{"RX-frames",228,17},{"write-attempts",232,1},{"counter-attempts",236,0},
		{"kicks",240,0},{"step-limit",244,601},{"trace-limit",248,33},{"trace-count",248,1},
		{"trace-direction",292,0},{"trace-command",296,9},{"trace-version",300,2},{"trace-features",304,7},
		{"trace-index",308,16384},{"initial-head",1320,8},{"final-TX-not-consumed",1348,16},
		{"final-host-head",1352,16},{"final-host-tail",1356,16},{"final-reserved",1364,1},
		{"TX-wire",1380,0},{"next-frame",17764+24,0},{"tail-padding",34148,1},
	}
	for _,tc:=range tests {t.Run(tc.name,func(t *testing.T){b:=fixture(t,"success-open.bin");le.PutUint32(b[tc.offset:],tc.value)
		if tc.name=="TX-wire" {b[1380]=1} // Original first frame is VERSION command0.
		if _,err:=decodeCapture(b,0x1234);err==nil {t.Fatal("accepted corrupt success")}
	})}
}
func TestRefuseStatusCorruption(t *testing.T) {
	for _,at:=range []int{16,20,24,28,32,36,40,44,48,52} {t.Run(fmt.Sprintf("offset-%d",at),func(t *testing.T){b:=fixture(t,"success-open.bin");le.PutUint32(b[at:],le.Uint32(b[at:])^1);if _,err:=decodeCapture(b,0x1234);err==nil {t.Fatal("accepted bad status")}})}
}
func TestRefuseShapeAndFalseCompletion(t *testing.T) {
	b:=fixture(t,"success-open.bin")
	for _,n:=range []int{0,79,80,34151} {if _,err:=decodeCapture(b[:n],0x1234);err==nil {t.Fatal(n)}}
	if _,err:=decodeCapture(append(b,0),0x1234);err==nil {t.Fatal("oversize")}
	if _,err:=decodeCapture(b,0);err==nil {t.Fatal("zero nonce")}
	for _,n:=range []string{"timeout-after-write.bin","refused-FDT.bin"}{b:=fixture(t,n);le.PutUint32(b[192:],1);if _,err:=decodeCapture(b,0x1234);err==nil {t.Fatal("false completion")}}
}
