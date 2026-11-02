package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}
type pipeInfo struct {
	Type     uint32
	ID       byte
	Pad      byte
	Packet   uint16
	Interval byte
	Tail     [3]byte
}

var usbGUID = guid{0xa5dcbf10, 0x6530, 0x11d2, [8]byte{0x90, 0x1f, 0, 0xc0, 0x4f, 0xb9, 0x51, 0xed}}
var cfg = syscall.NewLazyDLL("cfgmgr32.dll")
var winusb = syscall.NewLazyDLL("winusb.dll")
var report = map[string]any{"version": "G27-sahara-reset-1", "storage_write_APIs": false, "bulk_OUT_attempts": 0}
var events []map[string]any

func event(kind string, m map[string]any) { m["kind"] = kind; events = append(events, m) }
func boolcall(name string, args ...uintptr) error {
	r, _, e := winusb.NewProc(name).Call(args...)
	if r == 0 {
		return fmt.Errorf("%s: %w", name, e)
	}
	return nil
}
func interfaces() ([]string, error) {
	var size uint32
	r, _, _ := cfg.NewProc("CM_Get_Device_Interface_List_SizeW").Call(uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&usbGUID)), 0, 0)
	if r != 0 {
		return nil, fmt.Errorf("CM interface size CR=%x", r)
	}
	if size < 1 || size > 65536 {
		return nil, errors.New("interface list size guard")
	}
	b := make([]uint16, size)
	r, _, _ = cfg.NewProc("CM_Get_Device_Interface_ListW").Call(uintptr(unsafe.Pointer(&usbGUID)), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(size), 0)
	if r != 0 {
		return nil, fmt.Errorf("CM interface list CR=%x", r)
	}
	var found []string
	start := 0
	for i, c := range b {
		if c != 0 {
			continue
		}
		if i == start {
			break
		}
		s := string(utf16.Decode(b[start:i]))
		start = i + 1
		if strings.Contains(strings.ToLower(s), "usb#vid_05c6&pid_900e#") {
			found = append(found, s)
		}
	}
	return found, nil
}
func descriptor(h uintptr, typ, index byte, lang uint16) ([]byte, error) {
	b := make([]byte, 256)
	var n uint32
	e := boolcall("WinUsb_GetDescriptor", h, uintptr(typ), uintptr(index), uintptr(lang), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n)))
	runtime.KeepAlive(b)
	if e != nil {
		return nil, e
	}
	if n > uint32(len(b)) {
		return nil, errors.New("descriptor length")
	}
	return b[:n], nil
}
func stringDescriptor(h uintptr, index byte) (string, error) {
	if index == 0 {
		return "", errors.New("missing product string index")
	}
	lang, e := descriptor(h, 3, 0, 0)
	if e != nil {
		return "", e
	}
	if len(lang) < 4 || lang[1] != 3 || int(lang[0]) != len(lang) || len(lang)%2 != 0 {
		return "", errors.New("language descriptor")
	}
	b, e := descriptor(h, 3, index, binary.LittleEndian.Uint16(lang[2:4]))
	if e != nil {
		return "", e
	}
	if len(b) < 2 || b[1] != 3 || int(b[0]) != len(b) || len(b)%2 != 0 {
		return "", errors.New("product descriptor")
	}
	u := make([]uint16, (len(b)-2)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2+i*2:])
	}
	return string(utf16.Decode(u)), nil
}
func readPacket(h uintptr, ep byte) ([]byte, error) {
	b := make([]byte, 4096)
	var n uint32
	e := boolcall("WinUsb_ReadPipe", h, uintptr(ep), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(b)
	if n > uint32(len(b)) {
		return nil, errors.New("bulk length guard")
	}
	m := map[string]any{"bytes": n}
	if e != nil {
		m["error"] = e.Error()
	}
	if n >= 8 {
		m["cmd"] = binary.LittleEndian.Uint32(b)
		m["declared_length"] = binary.LittleEndian.Uint32(b[4:])
	}
	event("bulk_IN", m)
	return b[:n], e
}
func execute(mode, productHash, journal string) error {
	if mode != "describe" && mode != "probe" && mode != "reset" {
		return errors.New("mode must be describe/probe/reset")
	}
	expected, e := hex.DecodeString(productHash)
	if e != nil || len(expected) != 32 {
		return errors.New("exact product SHA256 required")
	}
	paths, e := interfaces()
	if e != nil {
		return e
	}
	report["matching_interfaces"] = len(paths)
	if len(paths) != 1 {
		return errors.New("expected one present 05c6:900e USB interface")
	}
	path := paths[0]
	hash := sha256.Sum256([]byte(path))
	report["interface_path_sha256"] = hex.EncodeToString(hash[:])
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	file, e := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OVERLAPPED, 0)
	if e != nil {
		return fmt.Errorf("CreateFile USB interface: %w", e)
	}
	defer syscall.CloseHandle(file)
	var h uintptr
	if e = boolcall("WinUsb_Initialize", uintptr(file), uintptr(unsafe.Pointer(&h))); e != nil {
		return e
	}
	defer winusb.NewProc("WinUsb_Free").Call(h)
	d, e := descriptor(h, 1, 0, 0)
	if e != nil {
		return e
	}
	if len(d) != 18 || d[0] != 18 || d[1] != 1 || binary.LittleEndian.Uint16(d[8:]) != 0x5c6 || binary.LittleEndian.Uint16(d[10:]) != 0x900e {
		return errors.New("USB VID/PID/descriptor guard")
	}
	product, e := stringDescriptor(h, d[15])
	if e != nil {
		return e
	}
	ph := sha256.Sum256([]byte(product))
	report["product_sha256"] = hex.EncodeToString(ph[:])
	if !strings.EqualFold(productHash, hex.EncodeToString(ph[:])) {
		return errors.New("phone product hash mismatch")
	}
	var iface [9]byte
	if e = boolcall("WinUsb_QueryInterfaceSettings", h, 0, uintptr(unsafe.Pointer(&iface[0]))); e != nil {
		return e
	}
	if e = validateInterface(iface[:]); e != nil {
		return e
	}
	report["interface_descriptor_hex"] = hex.EncodeToString(iface[:])
	var in, out byte
	var pipes []pipeInfo
	for i := byte(0); i < iface[4]; i++ {
		var pi pipeInfo
		if unsafe.Sizeof(pi) != 12 {
			return errors.New("WinUSB pipe ABI size")
		}
		if e = boolcall("WinUsb_QueryPipe", h, 0, uintptr(i), uintptr(unsafe.Pointer(&pi))); e != nil {
			return e
		}
		if pi.Type != 2 || pi.Packet == 0 {
			return errors.New("non-bulk pipe")
		}
		if pi.ID&0x80 != 0 {
			if in != 0 {
				return errors.New("duplicate IN")
			}
			in = pi.ID
		} else {
			if out != 0 {
				return errors.New("duplicate OUT")
			}
			out = pi.ID
		}
		pipes = append(pipes, pi)
	}
	if in != 0x81 || out != 0x01 {
		return errors.New("unexpected recovery endpoint pair")
	}
	report["pipes"] = pipes
	timeout := uint32(3000)
	for _, ep := range []byte{in, out} {
		if e = boolcall("WinUsb_SetPipePolicy", h, uintptr(ep), 3, 4, uintptr(unsafe.Pointer(&timeout))); e != nil {
			return e
		}
	}
	if mode == "describe" {
		return nil
	}
	// Retained Claude tool first attempted a read, then sent7 even on timeout.
	// Never upload a programmer, respond with an image, or request a RAM dump.
	initial, readErr := readPacket(h, in)
	report["pre_reset_read_bytes"] = len(initial)
	if readErr != nil {
		report["pre_reset_read_error"] = readErr.Error()
	}
	if mode == "probe" {
		return nil
	}
	if journal == "" {
		return errors.New("create-new host journal is required before reset")
	}
	j, e := os.OpenFile(journal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer j.Close()
	intent := map[string]any{"time_utc": time.Now().UTC().Format(time.RFC3339Nano), "intent": "ONE_SAHARA_RESET_ONLY", "product_sha256": productHash, "request_hex": hex.EncodeToString(resetRequest())}
	if e = json.NewEncoder(j).Encode(intent); e != nil {
		return e
	}
	if e = j.Sync(); e != nil {
		return e
	}
	req := resetRequest()
	var n uint32
	report["bulk_OUT_attempts"] = 1
	e = boolcall("WinUsb_WritePipe", h, uintptr(out), uintptr(unsafe.Pointer(&req[0])), uintptr(len(req)), uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(req)
	event("bulk_OUT", map[string]any{"bytes": n, "request_hex": hex.EncodeToString(req), "error": fmt.Sprint(e)})
	report["reset_sent_bytes"] = n
	if e != nil {
		return fmt.Errorf("reset write outcome may be ambiguous; do not automatically retry: %w", e)
	}
	if n != 8 {
		return errors.New("partial reset write; no retry")
	}
	for i := 0; i < 3; i++ {
		b, re := readPacket(h, in)
		if resetResponse(b) {
			report["reset_acknowledged"] = true
			return nil
		}
		if re != nil {
			break
		}
	}
	return errors.New("reset sent, acknowledgement unproven; inspect USB/control session before any other command")
}
func main() {
	mode := flag.String("mode", "describe", "describe/probe/reset")
	product := flag.String("product-sha256", "", "exact expected phone product hash")
	journal := flag.String("journal", "", "new host intent file; reset only")
	flag.Parse()
	report["mode"] = *mode
	e := execute(*mode, *product, *journal)
	report["events"] = events
	report["time_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	if e != nil {
		report["error"] = e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(report)
	if e != nil {
		os.Exit(1)
	}
}
