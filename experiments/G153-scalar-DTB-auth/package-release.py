"""Package the audited DTB-only temporary boot; never invoke its launcher."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent;p=w/'private'
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
load=lambda f:json.loads(f.read_text())
audit=load(p/'image-audit.json');assert audit['passed']and not audit['unexpected']
assert sha(p/'boot-G153-dtb-auth.img')==audit['image_sha256']
for name,digest in load(p/'candidate-source-hashes.json').items():assert sha(p/'candidate-source'/name)==digest
linked=load(p/'linked-sink-audit.json');assert linked['passed']and linked['BDS_sha256']==sha(p/'BdsDxe-linked.efi')
callbacks=load(p/'DTB-callback-audit.json');assert callbacks['passed']and callbacks['BDS_sha256']==audit['BDS_sha256']and callbacks['FD_sha256']==audit['FD_sha256']
for folder,count,names in [('observer-model-01',41,['OpenPasObserver.c','OpenPasObserver.h']),('error-capture-model-01',130,['OpenScmErrorCapture.c','OpenScmErrorCapture.h'])]:
 d=load(w.parent/'charging-G146/private'/folder/'tests.json');assert d['passed']and d['cases']==count
 for n in names:assert sha(w/n)==d['source_sha256'][n]
facade=load(p/'preflight-test-results.json');assert facade['passed']and facade['cases']==34 and facade['source_sha256']==sha(w/'OpenAdspPreflight.c')
for folder,count in [('admission-model-01',96),('adapter-model-02',72)]:
 d=load(p/folder/'tests.json');assert d['passed']and d['cases']==count
reader=load(p/'reader-verification.json');assert reader['passed']and reader['leaf_cases']==138 and sha(p/'G153-read-DSP.exe')==reader['exe_sha256']
for name,digest in reader['source_sha256'].items():assert sha(w/'report-reader'/name)==digest
negative=load(p/'reader-negative.json');assert negative['passed']and negative['WinPE_ARM64_exec_observed']and negative['reader_sha256']==reader['exe_sha256']
release=p/'release';assert not release.exists();release.mkdir()
files=[p/'boot-G153-dtb-auth.img',p/'G153-read-DSP.exe',w.parent/'charging-G139/private/G139-read-PIL.exe',w.parent/'charging-G128/private/G128-read-report.exe',w.parent/'charging-G132/private/G132-capture-G131-report.exe',w/'Boot-G153-DtbAuth.ps1',w/'Refresh-Existing-Debugger.ps1']
for f in files:shutil.copy2(f,release/f.name)
(release/'Boot-G153-DtbAuth.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G153-DtbAuth.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text('''G153: separately admitted DTB-only authentication diagnostic

One temporary boot, with the G144 memory map and existing 512 KiB original
DTB reservation unchanged. The original PIL submits DTB36 INIT/MEM_SETUP,
then may copy the exact 8376-byte adsp_dtb.b01 payload to9E980000. Before that
copy, refresh the reserved GCD/EFI map, three CPU pages and the known display
conflict checks. Before AUTH, repeat those checks, hash exactly8376 bytes,
compare the bound SHA256, then repeat the checks after hashing. This uses the
existing standalone OpenSha256 core, removing this module's direct BaseCryptLib
dependency. G146 reached the hash call but its crypto helper returned false,
so authentication was never forwarded. No secure-firmware AUTH refusal was observed.
The G153 outer table identities/revision retain the exact G146DSP1 body ABI
and G136LOG1 serial body; the reader checks these identities independently.

Only DTB36 AUTH is permitted. Pass its original successful result back to the
original loader so its POST branch can complete normally. Keep the original
SCM result separate from the public loader return. PRE/POST return values are
not directly observed. Stop before main-image loading/start; all main/shutdown
requests remain blocked. Never retry or issue shutdown on this same boot.
No authenticated-data rollback write is performed.

Checks cover the finite DTB experiment. They do not establish global DMA or
stage2 ownership, a production power lease, main DSP execution, GLINK readiness
or charging. Secure calls can alter state or fail to return. Both temporary
SCM/serial-cache pointers must restore before WinPE continuation.

No partition flash, BCD, installed driver/firmware, touch, scale, timeout or
certificate change. Never write modem_a or D:. A normal restart returns to
installed G80 and default WinPE. Keep physical recovery available. No recording
is needed initially; ask for fastboot only once fully staged and ready.

Collect all five tables from the fresh boot. G153-read-DSP reads the new OADP
and OSER table identities, retaining the old OSER body ABI. G139/128/132 readers
retain their observational OPIL, OPAS and raw OAPF interfaces. Cross-bind the
G153 preflight marker and finite DTB report; the old G144 footprint component
still describes memory_setup_only and is not a global ownership grant.

The launcher repeats all hashes and exact DEVICE_SERIAL/kalama/bootloader/slot-a
guards, refreshes only the owned one-shot debugger, rechecks fastboot, then
issues one boot command. VerifyOnly performs no phone/debugger operation.
The refresh guard expects PID17580 and debug/G146-20261025-160450/kd.txt.
''')
manifest={'campaign':'G153','action':'temporary_boot','DSP_start':'dtb_auth_diagnostic','PIL_inventory':True,'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86','files':[{'name':f.name,'bytes':f.stat().st_size,'sha256':sha(f)}for f in sorted(release.iterdir())]}
assert len(manifest['files'])==9
(release/'G153-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=p/'G153-dtb-auth.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for f in sorted(release.iterdir()):z.write(f,f.name)
result={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle),'release_manifest_sha256':sha(release/'G153-release.json'),'entries':10,'native_G153_boots':0,'partition_flashes':0}
(p/'release-package.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
