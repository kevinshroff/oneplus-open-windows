"""Package G155 only after the actual native G153 qualification is available.

Missing prerequisites fail before creating a release/ZIP. Never stages, invokes
fastboot, installs a task/driver or changes a debugger. No model-success mode.
"""
from pathlib import Path
import argparse,hashlib,json,shutil,zipfile
from qualification import qualified_dtb
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();load=lambda f:json.loads(f.read_text())
parser=argparse.ArgumentParser();parser.add_argument('--dtb-root',type=Path,default=w.parent/'charging-G153/private');args=parser.parse_args()
qualification=qualified_dtb(args.dtb_root) # First, before outputs.
audit=load(p/'image-audit.json');assert audit['passed']and not audit['unexpected']
assert sha(p/'boot-G155-main-auth.img')==audit['image_sha256']=='ccdfa94277975cc37b1f3f316d08a401b3127a93d148226412eecfb02d524a6a'
for name,h in load(p/'candidate-source-hashes.json').items():assert sha(p/'candidate-source'/name)==h
for name in ['linked-sink-audit.json','linked-main-read-audit.json','linked-orchestration-audit.json','DTB-callback-audit.json']:
 d=load(p/name);assert d['passed']and d['BDS_sha256']==audit['BDS_sha256']
for folder,count in [('adapter-model-01',96)]:
 d=load(p/folder/'tests.json');assert d['passed']and d['cases']==count
 for name,h in d['source_sha256'].items():assert sha(w/name)==h
guards=load(p/'analysis-guard-tests.json');assert guards['passed']and guards['cases']==99
for name,h in guards['source_sha256'].items():assert sha(w/name)==h
reader=load(p/'reader-verification.json');assert reader['passed']and reader['leaf_cases']==171 and sha(p/'G155-read-DSP.exe')==reader['exe_sha256']
for name,h in reader['source_sha256'].items():assert sha(w/'report-reader'/name)==h
syntax=load(p/'PowerShell-syntax.json');assert syntax['passed']and syntax['native_Windows_parser']is True
for name,h in syntax['source_sha256'].items():assert sha(w/name)==h
for check,count in [('qualification-tests.json',15),('release-guard-tests.json',3)]:
 d=load(p/check);assert d['passed']and d['cases']==count
 for name,h in d['source_sha256'].items():assert sha(w/name)==h
bridge=w.parent/'reboot-G154'
assert sha(bridge/'private/G154-install-arm64.exe')=='d6fb3079f3b02aef839724ec783be623af9b8c7c4ca9f8e174e599f2c631d5c7'
assert sha(bridge/'private/G154-FastbootOnce.efi')=='6b38dee219ac0f42054cacb0bd1ba9072621172fd9bcf5c7b0eb4532a327d2f7'
release=p/'release';assert not release.exists();release.mkdir()
files=[w.parent/'reboot-G154/private/G154-install-arm64.exe',w.parent/'reboot-G154/Restore-Project-EEM.ps1',p/'boot-G155-main-auth.img',p/'G155-read-DSP.exe',w.parent/'charging-G139/private/G139-read-PIL.exe',w.parent/'charging-G128/private/G128-read-report.exe',w.parent/'charging-G132/private/G132-capture-G131-report.exe',w/'Boot-G155-MainAuth.ps1',w/'Refresh-Existing-Debugger.ps1']
for f in files:shutil.copyfile(f,release/f.name)
(release/'Boot-G155-MainAuth.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G155-MainAuth.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'G153-qualification.json').write_text(json.dumps(qualification,indent=2)+'\n')
(release/'README.txt').write_text('''G155: one guarded original DTB/main loader diagnostic.

Require the real native G153 DTB public result and fresh native bootloader identity.
The G154 WinPE software-reset route is authorized for this iteration.
One temporary boot only. No partition flash, installed-driver/UI/BCD change,
remapping, PAS shutdown or same-boot retry. Both temporary pointers must restore.

DTB public completion precedes clearing the local main PreImage. The original
main MEM_SETUP/copy/AUTH/public return stay separate. Exact payload checking,
finite reservation/CPU/display admission and owner checks precede main AUTH.
They do not prove global DMA/stage2 ownership, a production power lease, DSP
execution, GLINK or real charging. Native calls/reads can still fault or hang.

Keep the phone unfolded and USB-connected to the Windows laptop.
Use the established bounded recovery procedure if the native test faults. A normal restart returns to installed firmware/default
WinPE. Preserve touch/mapping/packets,300% scale,Never timeouts and the test cert.
Never write modem_a/D: or read the forbidden C7B7000/C7B7008/B000000 addresses.

The launcher verifies exact file/tool hashes and phone DEVICE_SERIAL/kalama/slot-a/
bootloader mode. Refresh only the debugger identified by the native G153 result,
then recheck fastboot and issue one boot. The WinPE helper restores the normal
Windows loader before its one-shot bootloader reset. Preserve its job receipts. VerifyOnly performs no phone/debugger
operation. Request software fastboot only once staged/verified and immediately ready.

Collect all five tables from the new WinPE session. The G155 reader preserves
OADP/OSER raw bytes on failures; existing readers collect OPAS/OAPF/OPIL.
Analyze the same capture before another boot or secure request. A successful
public loader result is not proof of a working DSP/GLINK/charging subsystem.
''')
manifest={'campaign':'G155','action':'temporary_boot','DSP_start':'dtb_then_main_auth_diagnostic','PIL_inventory':True,'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],'DTB_qualification_sha256':qualification['native_analysis_sha256'],'predecessor_phone_session':qualification['phone_session'],'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86','files':[{'name':f.name,'bytes':f.stat().st_size,'sha256':sha(f)}for f in sorted(release.iterdir())]}
assert len(manifest['files'])==12
(release/'G155-release.json').write_text(json.dumps(manifest,indent=2)+'\n');bundle=p/'G155-main-auth.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for f in sorted(release.iterdir()):z.write(f,f.name)
(p/'release-package.json').write_text(json.dumps({'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle),'release_manifest_sha256':sha(release/'G155-release.json'),'entries':13,'DTB_prerequisite_native_verified':True,'native_G155_boots':0,'partition_flashes':0,'software_fastboot_helper':'G154 qualified one-shot EFI and ARM64 installer','post_boot_control_repair':'G154 exact dual-/16 source selection'},indent=2)+'\n')
print(json.dumps({'phase':'G155_packaged_not_staged','DTB_prerequisite_native_verified':True,'entries':13,'native_operations':0}))
