// Read-only interface enumeration. No device opens, IOCTLs or configuration calls.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

type guid struct {
	A uint32
	B uint16
	C uint16
	D [8]byte
}

type result struct {
	Name       string   `json:"name"`
	GUID       string   `json:"guid"`
	Status     string   `json:"status"`
	Units      uint32   `json:"buffer_utf16_units"`
	Count      int      `json:"present_interface_count"`
	PathHashes []string `json:"interface_path_sha256"`
	Error      string   `json:"error,omitempty"`
}

func enumerate(name string, id guid, sizeProc, listProc *syscall.LazyProc) result {
	r := result{Name: name, GUID: fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x", id.A, id.B, id.C, id.D[0], id.D[1], id.D[2:]), PathHashes: []string{}}
	for attempt := 0; attempt < 3; attempt++ {
		var count uint32
		// CM_GET_DEVICE_INTERFACE_LIST_PRESENT == 0; null instance means all
		// active interfaces of this one class, matching IoGetDeviceInterfaces.
		cr, _, _ := sizeProc.Call(uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&id)), 0, 0)
		runtime.KeepAlive(&id)
		if cr != 0 {
			r.Status, r.Error = "size_failed", fmt.Sprintf("CONFIGRET=0x%x", cr)
			return r
		}
		if count == 0 || count > 65536 {
			r.Status, r.Error = "invalid_size", fmt.Sprintf("units=%d", count)
			return r
		}
		buffer := make([]uint16, count)
		cr, _, _ = listProc.Call(uintptr(unsafe.Pointer(&id)), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(count), 0)
		runtime.KeepAlive(&id)
		runtime.KeepAlive(buffer)
		if cr == 0x1a { // CR_BUFFER_SMALL: retry the size/list pair on a race.
			continue
		}
		if cr != 0 {
			r.Status, r.Error = "list_failed", fmt.Sprintf("CONFIGRET=0x%x", cr)
			return r
		}
		r.Units = count
		for start := 0; start < len(buffer) && buffer[start] != 0; {
			end := start
			for end < len(buffer) && buffer[end] != 0 {
				end++
			}
			if end == len(buffer) {
				r.Status, r.Error = "unterminated_list", "missing string terminator"
				return r
			}
			path := string(utf16.Decode(buffer[start:end]))
			sum := sha256.Sum256([]byte(path))
			r.PathHashes = append(r.PathHashes, hex.EncodeToString(sum[:]))
			r.Count++
			start = end + 1
		}
		r.Status = "enumerated"
		return r
	}
	r.Status, r.Error = "unstable_list", "three buffer-size races"
	return r
}

func main() {
	dll := syscall.NewLazyDLL("cfgmgr32.dll")
	size := dll.NewProc("CM_Get_Device_Interface_List_SizeW")
	list := dll.NewProc("CM_Get_Device_Interface_ListW")
	if err := size.Find(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := list.Find(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if unsafe.Sizeof(guid{}) != 16 {
		panic("GUID ABI mismatch")
	}
	classes := []struct {
		name string
		id   guid
	}{
		{"disk_positive_control", guid{0x53f56307, 0xb6bf, 0x11d0, [8]byte{0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}}},
		{"SPI_required_SCM_provider", guid{0x55beca03, 0xba2c, 0x4fbc, [8]byte{0x9e, 0xfc, 0xee, 0x8e, 0xca, 0x56, 0xf0, 0xc7}}},
	}
	results := []result{}
	failed := false
	for _, c := range classes {
		r := enumerate(c.name, c.id, size, list)
		results = append(results, r)
		failed = failed || r.Status != "enumerated"
	}
	report := map[string]any{"version": "G24-provider-probe-1", "arch": runtime.GOARCH,
		"operation": "CM present-interface enumeration only", "interfaces": results}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if failed {
		os.Exit(2)
	}
}
