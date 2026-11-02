// highread: one-shot read-only discriminator for the >4GiB super zero-read bug.
// Opens the GPT disk by GUID (GENERIC_READ only), hashes fixed probe windows,
// reports sha256 + nonzero flags. No write, no arg parsing, no persistence.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

const (
	diskGUIDExpect = "bc5c99e5-16e0-14b8-b43a-de06f8ea711b"
	superBase      = uint64(0x2208000)
	userdataBase   = uint64(0x4582EC000)
)

type probe struct {
	Name string
	Abs  uint64
	Size uint64
}

func main() {
	disk, lastLBA, hdrGUID := discover()
	f, e := os.OpenFile(`\\.\`+disk, os.O_RDONLY, 0)
	if e != nil {
		fmt.Println(`{"error":"open","disk":` + jq(disk) + `,"detail":` + jq(e.Error()) + `}`)
		os.Exit(1)
	}
	defer f.Close()
	probes := []probe{
		{"super_A_policy_4.83GiB", superBase + 0x1345EC000, 1 << 20},
		{"super_B_3.5GiB", superBase + 0xE0000000, 1 << 20},
		{"super_C_4.0GiB_imgzero", superBase + 0x100000000, 1 << 20},
		{"super_E_6GiB_postimage", superBase + 0x180000000, 1 << 20},
		{"super_F_16GiB_postimage", superBase + 0x400000000, 1 << 20},
		{"userdata_8GiB", userdataBase + 0x200000000, 1 << 20},
		{"userdata_384GiB", userdataBase + 0x6000000000, 1 << 20},
	}
	type outT struct {
		Tool       string           `json:"tool"`
		Disk       string           `json:"disk"`
		GPT        string           `json:"gpt_disk_guid"`
		LastLBA    uint64           `json:"gpt_last_lba"`
		Probes     []map[string]any `json:"probes"`
	}
	o := outT{Tool: "highread-r0", Disk: disk, GPT: hdrGUID, LastLBA: lastLBA}
	for _, p := range probes {
		h, n, zero, re := hashRange(f, p.Abs, p.Size)
		m := map[string]any{"name": p.Name, "abs": p.Abs, "bytes": n,
			"sha256": h, "allzero": zero}
		if re != nil {
			m["error"] = re.Error()
		}
		o.Probes = append(o.Probes, m)
	}
	b, _ := json.MarshalIndent(o, "", " ")
	fmt.Println(string(b))
}

func hashRange(f *os.File, abs, size uint64) (string, uint64, bool, error) {
	h := sha256.New()
	buf := make([]byte, 64<<10)
	nonzero := false
	var done uint64
	var lastErr error
	for attempt := 0; attempt < 3 && done < size; {
		want := uint64(len(buf))
		if want > size-done {
			want = size - done
		}
		n, e := f.ReadAt(buf[:want], int64(abs+done))
		if e != nil || uint64(n) != want {
			lastErr = fmt.Errorf("read@%d:%d got %d err %v", abs+done, want, n, e)
			attempt++
			continue
		}
		chunk := buf[:want]
		for _, c := range chunk {
			if c != 0 {
				nonzero = true
				break
			}
		}
		h.Write(chunk)
		done += want
	}
	if done != size {
		return "", done, false, lastErr
	}
	return hex.EncodeToString(h.Sum(nil)), done, !nonzero, nil
}

func discover() (string, uint64, string) {
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf(`PhysicalDrive%d`, i)
		f, e := os.OpenFile(`\\.\`+name, os.O_RDONLY, 0)
		if e != nil {
			continue
		}
		sec := make([]byte, 4096)
		_, e = f.ReadAt(sec, 4096) // LBA1 on this 4Kn disk
		if e != nil || string(sec[:8]) != "EFI PART" {
			f.Close()
			continue
		}
		g := guid(sec, 56)
		if g == diskGUIDExpect {
			last := binary.LittleEndian.Uint64(sec[72:80])
			f.Close()
			return name, last, g
		}
		f.Close()
	}
	return "", 0, "not-found"
}

func guid(b []byte, o int) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[o:]), binary.LittleEndian.Uint16(b[o+4:]),
		binary.LittleEndian.Uint16(b[o+6:]), b[o+8:o+10], b[o+10:o+16])
}

func jq(s string) string { b, _ := json.Marshal(s); return string(b) }
