"""Offline isolated G711 derivative: adds fixed pool metadata reads only."""
import hashlib
import json
from pathlib import Path
import subprocess
import os

here=Path(__file__).resolve().parent
source=here.parent/'wifi-firmware-transfer-grouped/firmware_windows.go'
b=source.read_bytes()
assert hashlib.sha256(b).hexdigest()=='ca7fdd831737e06fcd6a56940cbe6621ae6fde44d9e8f100854e25d16c670fa6'
s=b.decode()
needle='\t\t\tfields := []struct {'
assert s.count(needle)==1
addition='''			// G742: twelve fixed eight-byte reads inside source-qualified pool, actual46 only.
			if *mode == "inspect-transfer" {
				metadata := make([]byte, 0, 0x60)
				for off := uint64(0x98); off < 0xf8; off += 8 {
					metadata = append(metadata, readRAM(x0+off, 8)...)
				}
				emit(map[string]any{"phase": "g742_pool_98_F7", "address": fmt.Sprintf("%016x", x0+0x98), "requested": 0x60, "actual_bytes": len(metadata), "hresult": 0, "raw_hex": hex.EncodeToString(metadata), "SDK_slot": 6, "pointer_dereferences_added": 0})
			}
'''
out=here/'metadata_windows.go'
out.write_text(s.replace(needle,addition+needle))
import difflib
(here/'SOURCE-DELTA.patch').write_text(''.join(difflib.unified_diff(
 s.splitlines(True),out.read_text().splitlines(True),
 fromfile='G711/firmware_windows.go',tofile='G742/metadata_windows.go')))
exe=here/'G742-Metadata-amd64.exe'
subprocess.run(['go','build','-trimpath','-ldflags=-buildid=','-o',str(exe),str(out)],
               env={**os.environ,'GOOS':'windows','GOARCH':'amd64','CGO_ENABLED':'0'},check=True)
(here/'METADATA-BUILD.json').write_text(json.dumps({
 'status':'offline compiled; pending independent root review; never staged/executed',
 'source_parent_sha256':hashlib.sha256(b).hexdigest(),
 'source_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),
 'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
 'added_reads':12,'added_bytes':96,'added_pointer_dereferences':0,
 'scope':'same G711 modes, use inspect-transfer only at actual46; no new resume or mutation'},indent=2)+'\n')
