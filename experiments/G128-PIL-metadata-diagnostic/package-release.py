"""Assemble the audited temporary-boot package. No phone or host operation."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent
audit=json.loads((w/'private/image-audit.json').read_text())
assert audit['passed']and audit['unexpected']==[]
assert json.loads((w/'private/preflight-test-results.json').read_text())['passed']
assert json.loads((w/'private/native-probe-model-03/tests.json').read_text())['passed']
tests=(w/'private/report-reader-tests.txt').read_text()
assert '\nPASS\n'in tests and '\nFAIL'not in tests
release=w/'private/release'
assert not release.exists()
release.mkdir()
for src in [w/'private/boot-G128-metadata.img',w/'private/G128-read-report.exe',w/'Boot-G128-Metadata.ps1']:
 shutil.copy2(src,release/src.name)
(release/'Boot-G128-Metadata.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G128-Metadata.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text("""G128: original PIL metadata diagnostic, temporary boot only

Checks original PIL/SCM loaded-code identity and both active ADSP configurations.
The G119 source-bound read-only adsp_ro view remains mounted while original
metadata and CPU-only ELF-header helpers run. Exact MDT digests, helper returns,
uncached arena reuse and cached buffer cleanup are recorded in ACPI OPAS.
The G119 reservation/file/cleanup report remains separately available as OAPF.
No public PIL Load, PAS, DSP start/shutdown, SCM method/slot replacement or
charging configuration is requested. The original heap/cache/MMU paths run.

Only verified OnePlus Open DEVICE_SERIAL / kalama, bootloader fastboot, slot a.
No partition flash command. A normal restart uses installed G80 firmware and
default WinPE recovery. No recording is needed initially. Do not restart old
flashing watchers. The launch repeats all file hashes and exact device checks.
If a command times out, inspect that run instead of submitting it again.
Boot-G128-Metadata.ps1 -VerifyOnly checks the release without phone commands.

Run G128-read-report.exe on the phone via the signed lab controller after boot.
It reads one OPAS table, checks the retained DSDT identity, validates the fixed
ABI/checksum/input/config/hash/status guards and returns JSON plus the raw table.
A valid report can describe a failed diagnostic; metadata_verified is separate.
Run the retained G124 OAPF reader for complete storage/facade cleanup results.
Neither report proves native DSP memory ownership, authentication, GLINK or
charging. The SCM ABI/slot attributes are inspection results only.

If temporary boot stalls, physical force-restart returns to installed firmware.
Never flash, format or repair modem_a / D:.
""")
sha=lambda b:hashlib.sha256(b).hexdigest()
manifest={'campaign':'G128','action':'temporary_boot','DSP_start':'not_armed',
 'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],
 'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86',
 'files':[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}for p in sorted(release.iterdir())]}
(release/'G128-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=w/'private/G128-metadata.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for p in sorted(release.iterdir()):z.write(p,p.name)
x={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle.read_bytes()),'release_manifest_sha256':sha((release/'G128-release.json').read_bytes()),'files':len(manifest['files'])+1,'native_phone_operations':0}
(w/'private/release-package.json').write_text(json.dumps(x,indent=2)+'\n')
print(json.dumps(x))
