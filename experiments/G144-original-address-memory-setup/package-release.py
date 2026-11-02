"""Package the audited memory-setup-only candidate; no host or phone command."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent;p=w/'private'
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
load=lambda f:json.loads(f.read_text())
audit=load(p/'image-audit.json');assert audit['passed'] and not audit['unexpected']
assert sha(p/'boot-G144-memory-setup.img')==audit['image_sha256']
for name,digest in load(p/'candidate-source-hashes.json').items():assert sha(p/'candidate-source'/name)==digest
linked=load(p/'linked-sink-audit.json');assert linked['passed'] and linked['BDS_sha256']==sha(p/'BdsDxe-linked.efi')
for folder,count in [('footprint-model-01',96),('adapter-model-01',63),('observer-model-02',44),('cpu-admission-model-01',29)]:
 d=load(p/folder/'tests.json');assert d['passed'] and d['cases']==count
reader=load(p/'reader-verification.json');assert reader['passed'] and sha(p/'G144-read-DSP.exe')==reader['exe_sha256']
for name,digest in reader['source_sha256'].items():assert sha(w/'report-reader'/name)==digest
negative=load(p/'reader-negative.json');assert negative['passed'] and negative['WinPE_ARM64_exec_observed']
release=p/'release';assert not release.exists();release.mkdir()
files=[p/'boot-G144-memory-setup.img',p/'G144-read-DSP.exe',
 w.parent/'charging-G139/private/G139-read-PIL.exe',
 w.parent/'charging-G128/private/G128-read-report.exe',
 w.parent/'charging-G132/private/G132-capture-G131-report.exe',
 w/'Boot-G144-MemorySetup.ps1',w/'Refresh-Existing-Debugger.ps1']
for f in files:shutil.copy2(f,release/f.name)
(release/'Boot-G144-MemorySetup.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G144-MemorySetup.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text('''G144: original-address DTB memory-setup-only diagnostic

One temporary boot. Fresh checks require the exact reserved PIL descriptor,
GCD/EFI coverage, no queried HOB/image/object/GOP overlap, stage-1 R/W identity
translations and raw44h normal-NC over9E980000..A3280000. The SCM hook page must
independently retain rawFFh WB and R/W access. No mapping/cache policy is changed.
These are limited memory-setup prerequisites, not global DMA ownership proof.

Submit DTB36 INIT and MEM_SETUP at9E980000:80000, keeping the original request
size. Always stop before payload copy, authentication, main-image request or
proxy/start actions, even if secure memory setup succeeds. The original secure
API can alter secure state or fail to return. Never retry or issue shutdown on
the same boot. Both temporary pointers must restore before WinPE continuation.
No DSP/GLINK/charging success is implied by this diagnostic.

Collect all five tables on this fresh boot. G144-read-DSP.exe reads the retained
G136 OADP/OSER wire ABI with G144 address/CPU rules. G139-read-PIL.exe retains its
observational OPIL ABI; G128-read-report.exe reads OPAS and the historical G132
reader retains raw OAPF. Cross-bind the G144 source marker and footprint state.

No partition flash, BCD, installed driver/firmware, touch, scale, timeout or
certificate change. Never write modem_a or D:. A normal restart returns to the
installed G80 and default WinPE. Keep physical recovery available; no recording
is needed initially. Ask for fastboot only once verified and immediately ready.

The launcher repeats all hashes and exact DEVICE_SERIAL/kalama/bootloader/slot-a
guards, refreshes only the owned one-shot debugger and checks fastboot again
immediately before one boot. VerifyOnly performs no phone/debugger operation.
The refresh guard expects PID9044 and the saved G139 boot's G136-prefixed log.
''')
manifest={'campaign':'G144','action':'temporary_boot','DSP_start':'memory_error_diagnostic','PIL_inventory':True,
 'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],
 'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86',
 'files':[{'name':f.name,'bytes':f.stat().st_size,'sha256':sha(f)}for f in sorted(release.iterdir())]}
assert len(manifest['files'])==9
(release/'G144-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=p/'G144-memory-setup.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for f in sorted(release.iterdir()):z.write(f,f.name)
result={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle),'release_manifest_sha256':sha(release/'G144-release.json'),'entries':10,'native_phone_operations':0}
(p/'release-package.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
