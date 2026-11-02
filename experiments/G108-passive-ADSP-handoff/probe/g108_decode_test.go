package main

import "testing"

func fixture() []byte {
	b := make([]byte, captureBytes)
	le.PutUint32(b, 80)
	le.PutUint32(b[4:], 1)
	copy(b[8:], "OG108MR1")
	for o, v := range map[int]uint32{16: 26300, 20: 8, 28: 576, 32: 1, 40: 14, 44: 1, 48: 1, 92: 127, 100: 14, 120: 7} {
		le.PutUint32(b[o:], v)
	}
	le.PutUint64(b[80:], 123)
	le.PutUint64(b[104:], 100)
	le.PutUint64(b[112:], 1000100)
	addresses := []uint64{0x81d00000, 0x81eff000, 0x81a00000, 0xa7605000, 0x146aa94c, 0x81d04000, 0x81d84000}
	sizes := []uint32{0x3000, 0x1000, 0x40000, 0x8000, 200, 0x80000, 0x20000}
	offset := uint32(0)
	for i, size := range sizes {
		at := 128 + 32*i
		le.PutUint64(b[at:], addresses[i])
		le.PutUint32(b[at+8:], size)
		le.PutUint32(b[at+12:], offset)
		kind := uint32(i + 1)
		if i >= 5 {
			kind = 6
		}
		le.PutUint32(b[at+24:], kind)
		if i == 5 {
			le.PutUint32(b[at+16:], 0xfffe)
			le.PutUint32(b[at+20:], 0xfffe)
		}
		if i == 6 {
			le.PutUint32(b[at+20:], 2)
		}
		offset += 2 * size
	}
	le.PutUint32(b[96:], offset)
	le.PutUint32(b[124:], offset)
	return b
}
func TestCompleteCapture(t *testing.T) {
	b := fixture()
	v, e := decodeCapture(b, 123)
	if e != nil || v["operation_code"] != uint32(0) {
		t.Fatal(v, e)
	}
}
func TestMalformedCapture(t *testing.T) {
	for _, kind := range []string{"magic", "nonce", "region_count", "payload", "read_count", "map_count", "bad_address", "bad_size", "bad_offset", "bad_hosts", "duplicate_hosts", "time", "short"} {
		t.Run(kind, func(t *testing.T) {
			b := fixture()
			switch kind {
			case "magic":
				b[8] ^= 1
			case "nonce":
				b[80] ^= 1
			case "region_count":
				le.PutUint32(b[120:], 8)
			case "payload":
				le.PutUint32(b[124:], 0x500001)
			case "read_count":
				le.PutUint32(b[96:], 0xffffffff)
			case "map_count":
				le.PutUint32(b[100:], 15)
			case "bad_address":
				b[128] ^= 1
			case "bad_size":
				le.PutUint32(b[136:], 0xffffffff)
			case "bad_offset":
				le.PutUint32(b[140:], 0xffffffff)
			case "bad_hosts":
				le.PutUint32(b[128+6*32+20:], 1)
			case "duplicate_hosts":
				le.PutUint32(b[128+6*32+16:], 0xfffe)
				le.PutUint32(b[128+6*32+20:], 0xfffe)
			case "time":
				le.PutUint64(b[112:], 99)
			case "short":
				b = b[:80]
			}
			if _, e := decodeCapture(b, 123); e == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}
