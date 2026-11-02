"""Package the audited one-use DSP diagnostic. No device operation."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
a=json.loads((p/'image-audit.json').read_text());assert a['passed']and not a['unexpected']
checks=[('adapter-model-04/tests.json',47),('footprint-model-01/tests.json',68),('metadata-probe-model-01/tests.json',31),('observer-model-02/tests.json',55),('admission-model-01.json',18),('public-config-original-01.json',14),('relocated-original-range-01.json',2),('preflight-test-results.json',33)]
for name,count in checks:
 d=json.loads((p/name).read_text());assert d['passed']and d['cases']==count
assert '\nPASS\n'in(p/'reader-tests.txt').read_text()
lib=p/'candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
d=json.loads((p/'preflight-test-results.json').read_text());assert d['source_sha256']==sha(lib/'OpenAdspPreflight.c')
d=json.loads((p/'adapter-model-04/tests.json').read_text());assert all(d['source_SHA256'][n]==sha(lib/n)for n in ['OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenDspAdmission.c'])
assert sha(p/'boot-G134-guarded.img')==a['image_sha256']
release=p/'release';assert not release.exists();release.mkdir()
files=[p/'boot-G134-guarded.img',p/'G134-read-DSP.exe',w.parent/'charging-G128/private/G128-read-report.exe',w.parent/'charging-G132/private/G132-capture-G131-report.exe',w/'Boot-G134-Guarded.ps1',w/'Refresh-Existing-Debugger.ps1']
for f in files:shutil.copy2(f,release/f.name)
(release/'Boot-G134-Guarded.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G134-Guarded.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text('''G134: one guarded original-loader/DSP diagnostic

Temporary fastboot boot only, with no partition flash. Mode16 continues to the
existing default WinPE after a returning attempt. Firmware AUTO stays empty.
This candidate can issue PAS initialization, memory setup and authentication
for ADSP DTB36, then main1, exactly once after its admission checks. It is an
active hardware test. It is not a read-only firmware inventory or a production
charger implementation. Keep physical recovery available for the first test.

The candidate uses the native-G133-reserved Kernel window: DTB A9F80000/80000,
main AA000000/4880000. Fixed compiled/GCD/EFI/HOB/image/object checks, current GOP
exclusion and stage-1 CPU read/write/identity/WB checks precede the SCM observer.
These checks are not proof of global DMA or stage-2 policy. The original public
custom-config method is used, retaining adsp_ro through the request. Its runtime
profiles are copied from verified metadata; main PreImage is cleared after the
separate DTB request. Backup/post-image/shutdown paths are disallowed. No INI,
FAT, BCD, modem_a/D:, touch, scaling, timeout or certificate write is performed.
The OEM DSP firmware can initialize hardware; the AP diagnostic does not program
charger registers or invent battery/temperature policy.

Every PAS stage records original transport status, all four results, filtered
status, entry/return and refusal. Both transport and primary service result must
be accepted. There is no retry or blind shutdown after a failure. A successful
authentication return is distinct from a running DSP, GLINK or working charging.
SMC latency is not bounded by this observer. A non-return requires physical
recovery; a Windows kernel debugger cannot recover an in-progress UEFI/SMC call.
The callback is restored and independently checked before normal continuation;
failed restoration stops the firmware with its context retained.

G134-read-DSP.exe reads OADP, preserving a bounded raw table even when decoding
fails. G128-read-report.exe reads the original, pre-request metadata OPAS.
G132-capture-G131-report.exe keeps its historical filename and captures raw OAPF;
the G134 preflight text intentionally has a new guarded-request framing. Collect
all three on this boot before restarting. No video is needed initially.

The launcher verifies all hashes and exact DEVICE_SERIAL/kalama/bootloader/slot-a
identity, refreshes the existing one-shot debugger with an initial command ending
in g, then rechecks bootloader identity immediately before fastboot boot. It
accepts the known G133 debugger PID/log only. This is one reviewed test, not a
reusable automatic retry. -VerifyOnly performs no phone or debugger command.
Normal restart returns to installed G80 and default recovery WinPE. Request
fastboot only when staged and immediately ready; it times out after about a minute.
''')
manifest={'campaign':'G134','action':'temporary_boot','DSP_start':'guarded_one_use','image_sha256':a['image_sha256'],'FD_sha256':a['FD_sha256'],'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86','files':[{'name':f.name,'bytes':f.stat().st_size,'sha256':sha(f)}for f in sorted(release.iterdir())]}
(release/'G134-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=p/'G134-guarded.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for f in sorted(release.iterdir()):z.write(f,f.name)
result={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle),'release_manifest_sha256':sha(release/'G134-release.json'),'entries':len(manifest['files'])+1,'native_phone_operations':0}
(p/'release-package.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
