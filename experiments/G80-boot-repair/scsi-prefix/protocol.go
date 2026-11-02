package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const chunkBytes = 65536
const chunkCount = 16384

var planSHA string // set at build; empty builds cannot use a plan.
type pinnedPlan struct{ data []byte }

func parsePlan(b []byte) (pinnedPlan, error) {
	h := sha256.Sum256(b)
	if planSHA == "" || hex.EncodeToString(h[:]) != planSHA || len(b) != 256+chunkCount*64 {
		return pinnedPlan{}, fmt.Errorf("plan identity/size")
	}
	if string(b[:8]) != "OP80P01\x00" || binary.LittleEndian.Uint32(b[8:]) != 1 || binary.LittleEndian.Uint32(b[12:]) != 4096 || binary.LittleEndian.Uint32(b[16:]) != chunkBytes || binary.LittleEndian.Uint32(b[20:]) != chunkCount || binary.LittleEndian.Uint64(b[24:]) != 1<<30 || binary.LittleEndian.Uint64(b[32:]) != 64 {
		return pinnedPlan{}, fmt.Errorf("plan geometry")
	}
	return pinnedPlan{b}, nil
}
func (p pinnedPlan) hashes(i int, undo bool) ([]byte, []byte) {
	a := p.data[256+i*64 : 256+i*64+32]
	b := p.data[256+i*64+32 : 256+i*64+64]
	if undo {
		return b, a
	}
	return a, b
}
func (p pinnedPlan) imageHash(undo bool) []byte {
	if undo {
		return p.data[48:80]
	}
	return p.data[80:112]
}
func makeCDB(op byte, lba uint32, n int, group byte) ([16]byte, error) {
	var c [16]byte
	if (op != 0x28 && op != 0x2a) || n <= 0 || n > chunkBytes || n%4096 != 0 || uint64(lba)+uint64(n/4096) > 0x40000 {
		return c, fmt.Errorf("bounded READ10/WRITE10 required")
	}
	if group != 0 && !(group == 31 && op == 0x28 && lba == 0 && n == 4096) {
		return c, fmt.Errorf("only exact commit read may use group31")
	}
	if op == 0x2a && (n != chunkBytes || lba%16 != 0 || group != 0) {
		return c, fmt.Errorf("only aligned64KiB writes")
	}
	c[0] = op
	binary.BigEndian.PutUint32(c[2:6], lba)
	c[6] = group
	binary.BigEndian.PutUint16(c[7:9], uint16(n/4096))
	return c, nil
}

type chunkTransport interface {
	read(uint32, []byte) error
	write(uint32, []byte) error
}

func applyChunk(t chunkTransport, i int, data []byte, old, want []byte) (bool, error) {
	if i < 0 || i >= chunkCount || len(data) != chunkBytes || len(old) != 32 || len(want) != 32 {
		return false, fmt.Errorf("chunk shape")
	}
	hash := sha256.Sum256(data)
	if !bytes.Equal(hash[:], want) {
		return false, fmt.Errorf("proposed chunk is not pinned")
	}
	current := make([]byte, chunkBytes)
	lba := uint32(i * 16)
	if e := t.read(lba, current); e != nil {
		return false, e
	}
	hash = sha256.Sum256(current)
	if bytes.Equal(hash[:], want) {
		return false, nil
	}
	if !bytes.Equal(hash[:], old) {
		return false, fmt.Errorf("unknown current chunk%d; no write", i)
	}
	if e := t.write(lba, data); e != nil {
		return false, e
	}
	if e := t.read(lba, current); e != nil {
		return false, e
	}
	hash = sha256.Sum256(current)
	if !bytes.Equal(hash[:], want) {
		return false, fmt.Errorf("readback differs at chunk%d", i)
	}
	return true, nil
}
