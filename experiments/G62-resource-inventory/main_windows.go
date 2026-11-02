// SPDX-License-Identifier: MIT
// Read-only Configuration Manager queries. No device open, IOCTL, installation,
// reenumeration, hardware mapping, register access or configuration mutation.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"
	"unsafe"
)

var cm = syscall.NewLazyDLL("cfgmgr32.dll")
var pListSize = cm.NewProc("CM_Get_Device_ID_List_SizeW")
var pList = cm.NewProc("CM_Get_Device_ID_ListW")
var pLocate = cm.NewProc("CM_Locate_DevNodeW")
var pStatus = cm.NewProc("CM_Get_DevNode_Status")
var pProp = cm.NewProc("CM_Get_DevNode_Registry_PropertyW")
var pFirst = cm.NewProc("CM_Get_First_Log_Conf")
var pNextLog = cm.NewProc("CM_Get_Next_Log_Conf")
var pFreeLog = cm.NewProc("CM_Free_Log_Conf_Handle")
var pNextRes = cm.NewProc("CM_Get_Next_Res_Des")
var pDataSize = cm.NewProc("CM_Get_Res_Des_Data_Size")
var pData = cm.NewProc("CM_Get_Res_Des_Data")
var pFreeRes = cm.NewProc("CM_Free_Res_Des_Handle")
var failures []string
var descriptors, rawBytes int

// uintptr arguments originate in pointer conversions at the call site. Keep
// those objects on the heap and alive through the nested DLL call.
//
//go:uintptrescapes
func cr(p *syscall.LazyProc, args ...uintptr) uint32 { v, _, _ := p.Call(args...); return uint32(v) }
func fail(s string)                                  { failures = append(failures, s) }

type ResourceSummary struct {
	Count        int    `json:"descriptor_count"`
	RawBytes     int    `json:"raw_bytes"`
	StreamSHA256 string `json:"raw_stream_sha256"`
	Complete     bool   `json:"enumeration_complete"`
	EndCR        uint32 `json:"end_query_cr"`
}
type LogConfig struct {
	Index       int             `json:"index"`
	Enumeration ResourceSummary `json:"resource_enumeration"`
	Resources   []Descriptor    `json:"resources"`
}

var resourceDeadline time.Time

type Configs struct {
	QueryCR  uint32      `json:"first_query_cr"`
	EndCR    uint32      `json:"end_query_cr"`
	Complete bool        `json:"enumeration_complete"`
	Logs     []LogConfig `json:"logs"`
}
type Device struct {
	ID           string            `json:"id"`
	LocateCR     uint32            `json:"locate_cr"`
	StatusCR     uint32            `json:"status_cr"`
	Status       uint32            `json:"status"`
	Problem      uint32            `json:"problem"`
	Description  string            `json:"description"`
	Service      string            `json:"service"`
	PropertiesCR map[string]uint32 `json:"property_cr"`
	Alloc        Configs           `json:"allocated"`
	Boot         Configs           `json:"boot"`
}

func property(dn, prop uint32) (string, uint32) {
	var typ uint32
	b := make([]uint16, 2048)
	n := uint32(len(b) * 2)
	r := cr(pProp, uintptr(dn), uintptr(prop), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0)
	if r != 0 {
		return "", r
	}
	if typ != 1 || n < 2 || n > uint32(len(b)*2) || n%2 != 0 {
		fail(fmt.Sprintf("property layout differs dn%d prop%d type%d size%d", dn, prop, typ, n))
		return "", 0xffffffff
	}
	return syscall.UTF16ToString(b[:n/2]), 0
}
func resources(log uintptr) (out []Descriptor, summary ResourceSummary) {
	out = make([]Descriptor, 0)
	previous := log
	isRes := false
	completeReads := true
	stream := sha256.New()
	defer func() {
		summary.StreamSHA256 = hex.EncodeToString(stream.Sum(nil))
		if isRes {
			if x := cr(pFreeRes, previous); x != 0 {
				fail(fmt.Sprintf("free descriptor CR0x%x", x))
				summary.Complete = false
			}
		}
	}()
	store := func(d Descriptor) { out = appendDescriptor(out, d) }
	for count := 0; count <= 8192; count++ {
		var next uintptr
		var typ uint32
		r := cr(pNextRes, uintptr(unsafe.Pointer(&next)), previous, 0, uintptr(unsafe.Pointer(&typ)), 0)
		if isRes {
			if x := cr(pFreeRes, previous); x != 0 {
				fail(fmt.Sprintf("free descriptor CR0x%x", x))
				completeReads = false
			}
			isRes = false
		}
		summary.EndCR = r
		if r != 0 {
			summary.Complete = r == 15 && completeReads
			if r != 15 {
				fail(fmt.Sprintf("resource enumeration CR0x%x", r))
			}
			return
		}
		previous = next
		isRes = true
		if count == 8192 || descriptors >= 32768 || time.Now().After(resourceDeadline) {
			fail("descriptor count/time cap reached")
			return
		}
		descriptors++
		summary.Count++
		d := Descriptor{Type: typ, Repeat: 1}
		var n uint32
		r = cr(pDataSize, uintptr(unsafe.Pointer(&n)), next, 0)
		if r != 0 || n == 0 || n > 65536 || rawBytes+int(n) > 2*1024*1024 {
			d.Error = fmt.Sprintf("data size/cap CR0x%x bytes%d", r, n)
			fail(d.Error)
			completeReads = false
			store(d)
			continue
		}
		d.Bytes = n
		b := make([]byte, n)
		r = cr(pData, next, uintptr(unsafe.Pointer(&b[0])), uintptr(n), 0)
		if r != 0 {
			d.Error = fmt.Sprintf("data CR0x%x", r)
			fail(d.Error)
			completeReads = false
		} else {
			rawBytes += int(n)
			summary.RawBytes += int(n)
			header := make([]byte, 8)
			binary.LittleEndian.PutUint32(header, typ)
			binary.LittleEndian.PutUint32(header[4:], n)
			stream.Write(header)
			stream.Write(b)
			d.Raw = hex.EncodeToString(b)
			v, e := decodeResource(typ, b)
			if e != nil {
				d.DecodeError = e.Error()
			} else {
				d.Decoded = &v
			}
		}
		store(d)
	}
	return
}

func configurations(dn, kind uint32) Configs {
	c := Configs{Logs: make([]LogConfig, 0)}
	var h uintptr
	c.QueryCR = cr(pFirst, uintptr(unsafe.Pointer(&h)), uintptr(dn), uintptr(kind))
	if c.QueryCR != 0 {
		c.Complete = c.QueryCR == 14
		if !c.Complete {
			fail(fmt.Sprintf("first log dn%d kind%d CR0x%x", dn, kind, c.QueryCR))
		}
		return c
	}
	for i := 0; i < 8; i++ {
		rows, summary := resources(h)
		c.Logs = append(c.Logs, LogConfig{Index: i, Resources: rows, Enumeration: summary})
		var next uintptr
		r := cr(pNextLog, uintptr(unsafe.Pointer(&next)), h, 0)
		if x := cr(pFreeLog, h); x != 0 {
			fail(fmt.Sprintf("free log CR0x%x", x))
		}
		c.EndCR = r
		if r != 0 {
			c.Complete = r == 14
			if !c.Complete {
				fail(fmt.Sprintf("next log CR0x%x", r))
			}
			return c
		}
		h = next
	}
	if x := cr(pFreeLog, h); x != 0 {
		fail(fmt.Sprintf("free log at cap CR0x%x", x))
	}
	fail("logical configuration cap reached")
	return c
}
func deviceIDs() ([]string, error) {
	var n uint32
	r := cr(pListSize, uintptr(unsafe.Pointer(&n)), 0, 0x100)
	if r != 0 || n < 2 || n > 65536 {
		return nil, fmt.Errorf("present ID list size CR0x%x size%d", r, n)
	}
	b := make([]uint16, n)
	r = cr(pList, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(n), 0x100)
	if r != 0 {
		return nil, fmt.Errorf("present ID list CR0x%x", r)
	}
	if b[len(b)-1] != 0 {
		return nil, errors.New("ID list missing final terminator")
	}
	ids := make([]string, 0)
	at := 0
	for i, v := range b {
		if v == 0 {
			if i == at {
				sort.Strings(ids)
				return ids, nil
			}
			if len(ids) >= 512 {
				return nil, errors.New("present device cap reached")
			}
			ids = append(ids, syscall.UTF16ToString(b[at:i]))
			at = i + 1
		}
	}
	return nil, errors.New("ID list missing double terminator")
}
func firmware() (string, error) {
	p := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, _ := p.Call(0x41435049, 0x54445344, 0, 0)
	if n != 576 {
		return "", fmt.Errorf("DSDT length%d differs from originalG17", n)
	}
	b := make([]byte, n)
	got, _, _ := p.Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return "", errors.New("DSDT short read")
	}
	s := sha256.Sum256(b)
	h := hex.EncodeToString(s[:])
	if h != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return "", errors.New("DSDT differs from originalG17")
	}
	return h, nil
}
func capture(token string) (any, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 || !validToken(token) {
		return nil, errors.New("native ARM64/eight CPU/token guard failed")
	}
	h, e := firmware()
	if e != nil {
		return nil, e
	}
	dest := filepath.Join(`X:\OpenG17\payloads`, "G62-resources-"+token+".json")
	f, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	resourceDeadline = time.Now().Add(30 * time.Second)
	ids, e := deviceIDs()
	if e != nil {
		return nil, e
	}
	rows := make([]Device, 0, len(ids))
	for _, id := range ids {
		d := Device{ID: id, PropertiesCR: map[string]uint32{}}
		u := syscall.StringToUTF16(id)
		var dn uint32
		d.LocateCR = cr(pLocate, uintptr(unsafe.Pointer(&dn)), uintptr(unsafe.Pointer(&u[0])), 0)
		if d.LocateCR == 0 {
			d.StatusCR = cr(pStatus, uintptr(unsafe.Pointer(&d.Status)), uintptr(unsafe.Pointer(&d.Problem)), uintptr(dn), 0)
			d.Description, d.PropertiesCR["description"] = property(dn, 1)
			d.Service, d.PropertiesCR["service"] = property(dn, 5)
			d.Alloc = configurations(dn, 2)
			d.Boot = configurations(dn, 3)
		} else {
			fail(fmt.Sprintf("present device locate CR0x%x", d.LocateCR))
		}
		rows = append(rows, d)
	}
	report := map[string]any{"version": "G62-resource-snapshot2", "native_arch": runtime.GOARCH, "processors": runtime.NumCPU(), "DSDT_sha256": h, "device_filter": "CM_GETIDLIST_FILTER_PRESENT", "resource_lists": "allocated and boot recorded separately", "descriptor_width": "native64, pack1 SDK26100", "devices": rows, "descriptor_count": descriptors, "descriptor_encoding": "lossless-consecutive-IRQ-RLE1", "raw_descriptor_bytes": rawBytes, "enumeration_warnings": failures, "hardware_register_reads": 0, "hardware_register_writes": 0, "native_device_or_configuration_mutations": 0}
	b, e := json.Marshal(report)
	if e != nil {
		return nil, e
	}
	if len(b) > 4*1024*1024 {
		return nil, errors.New("snapshot JSON cap exceeded")
	}
	b = append(b, '\n')
	if _, e = f.Write(b); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	return map[string]any{"path": dest, "bytes": len(b), "sha256": hex.EncodeToString(sum[:]), "devices": len(rows), "descriptors": descriptors, "warnings": len(failures), "hardware_accesses": 0, "configuration_mutations": 0}, nil
}
func main() {
	var v any
	var e error
	if len(os.Args) != 3 || os.Args[1] != "capture" {
		e = errors.New("usage: capture TOKEN")
	} else {
		v, e = capture(os.Args[2])
	}
	if e != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": e.Error()})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "result": v})
}
