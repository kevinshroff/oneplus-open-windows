"""Package audited G139. This script performs no host/phone operation."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
audit=json.loads((p/'image-audit.json').read_text());assert audit['passed'] and not audit['unexpected']
assert sha(p/'boot-G139-combined-memory.img')==audit['image_sha256']
source=json.loads((p/'candidate-source-hashes.json').read_text())
for name,h in source.items():assert sha(p/'candidate-source'/name)==h
linked=json.loads((p/'linked-sink-audit.json').read_text())
assert linked['passed'] and linked['BDS_sha256']==sha(p/'BdsDxe-linked.efi')
for folder,count in [('footprint-model-03',79),('cpu-model-01',15),('publisher-model-03',14)]:
 r=json.loads((p/folder/'tests.json').read_text());assert r['passed'] and r['cases']==count
life=json.loads((p/'preflight-test-results.json').read_text());assert life['passed'] and life['cases']==34
reader=json.loads((p/'reader-verification.json').read_text());assert reader['passed'] and sha(p/'G139-read-PIL.exe')==reader['exe_sha256']
for name,h in reader['source_sha256'].items():assert sha(w/'report-reader'/name)==h
negative=json.loads((p/'reader-negative.json').read_text());assert not negative['ok'] and negative['error']=='expected one G139 OPIL table; found 0'
release=p/'release';assert not release.exists();release.mkdir()
files=[p/'boot-G139-combined-memory.img',p/'G139-read-PIL.exe',
 w.parent/'charging-G136/private/G136-read-DSP.exe',
 w.parent/'charging-G128/private/G128-read-report.exe',
 w.parent/'charging-G132/private/G132-capture-G131-report.exe',
 w/'Boot-G139-CombinedMemory.ps1',w/'Refresh-Existing-Debugger.ps1']
for f in files:shutil.copy2(f,release/f.name)
(release/'Boot-G139-CombinedMemory.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G139-CombinedMemory.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text('''G139: combined in-window inventory and G136 secure-error capture

One temporary fastboot boot. The new OPIL report queries memory maps, bounded
HOBs, loaded images, firmware objects, GOP framebuffer bounds and stage-1 CPU
translations for9E980000..A3280000. It records raw PAR attribute tags, permission
faults and physical aliases across18688 pages. It does not read/write that target
memory, change mappings/reservations, invoke in-window PAS, or grant ownership.
The policy limits in this report come from G138 shipped devcfg captures, not a
live read of secure globals. GOP does not cover every possible display/DMA use.

G136's request/error sink and old Kernel admission remain unchanged: image36
INIT/MEM_SETUP atA9F80000:80000, then stop before payload/auth/main even if setup
is accepted. Exact original pointers must restore; failed restoration stops
continuation. No main request, AUTH, shutdown or same-boot retry is allowed.
The original secure API may alter secure state or fail to return. This package
has not established native DSP, GLINK, battery charging or safe in-window RAM.

Collect all five tables from the same fresh boot: G139-read-PIL.exe reads OPIL;
G136-read-DSP.exe reads OADP/OSER; G128-read-report.exe reads OPAS; the historical
G132-capture-G131-report.exe reads raw OAPF. OPIL collection completion never means
memory is eligible. Available stable raw tables are kept when decoding fails.

Boot image only; no partition flash, BCD/FAT/INI, installed firmware/driver,
touch, 300% scale, Never timeout or test certificate change. Never write modem_a
or D:. Normal restart returns to installed G80 and default WinPE recovery.
No recording is needed initially. Keep physical recovery available.

The launcher repeats file hashes and exact DEVICE_SERIAL/kalama/bootloader/slot-a
checks, refreshes only the guarded one-shot debugger and rechecks fastboot
immediately before one boot. Its unchanged debugger helper expects the known
G134 PID2532/log. VerifyOnly issues no phone or debugger commands. Launch only
after a fresh human-ready cue; earlier fastboot messages expire quickly.
''')
manifest={'campaign':'G139','action':'temporary_boot','DSP_start':'memory_error_diagnostic','PIL_inventory':True,
 'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],
 'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86',
 'files':[{'name':f.name,'bytes':f.stat().st_size,'sha256':sha(f)} for f in sorted(release.iterdir())]}
assert len(manifest['files'])==9
(release/'G139-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=p/'G139-combined-memory.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1) as z:
 for f in sorted(release.iterdir()):z.write(f,f.name)
result={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle),'release_manifest_sha256':sha(release/'G139-release.json'),'entries':10,'native_phone_operations':0}
(p/'release-package.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
