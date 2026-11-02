"""Assemble the audited temporary-boot package. No phone or host operation."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent
audit=json.loads((w/'private/image-audit.json').read_text())
assert audit['passed']and audit['unexpected']==[]
assert json.loads((w/'private/preflight-test-results.json').read_text())['passed']
tests=(w/'private/report-reader-tests.txt').read_text()
assert '\nPASS\n'in tests and '\nFAIL'not in tests
release=w/'private/release'
assert not release.exists()
release.mkdir()
for src in [w/'private/boot-G119-preflight.img',w/'private/G119-read-report.exe',w/'Boot-G119-Preflight.ps1']:
 shutil.copy2(src,release/src.name)
(release/'Boot-G119-Preflight.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G119-Preflight.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text('''G119: finite UEFI firmware-file and reservation preflight

This temporarily boots the verified image for OnePlus Open DEVICE_SERIAL / kalama,
slot a. It contains no partition flash command and no DSP startup request.
The normal installed firmware and WinPE recovery entry remain available after
a normal restart. The temporary firmware changes the PIL reservation and uses
a source-bound read-only view for the 64 captured ADSP inputs. It does not
enable charging or install a battery/graphics driver.

The lab will launch immediately after the phone is available in bootloader
fastboot. No recording is needed initially. Do not start an old recovery or
flashing watcher. Boot-G119-Preflight.ps1 -VerifyOnly checks files and scripts
without sending a phone command. Actual launch repeats file hashes and checks
the exact device identity. If a command times out, inspect its saved run.

Once Windows/WinPE starts, run G119-read-report.exe on the phone through the
existing signed lab controller. It reads the OEM ACPI OAPF report and refuses
a missing/duplicate table or changed DSDT. Its JSON distinguishes file,
reservation and cleanup results. DSP and physical display ownership are not
qualified by this preflight. The report reader does not write any files.

If temporary boot stalls, a normal physical force-restart returns to the
installed firmware. Do not flash, format or repair modem_a / D:.
''')
sha=lambda b:hashlib.sha256(b).hexdigest()
manifest={'campaign':'G119','action':'temporary_boot','DSP_start':'not_armed',
 'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],
 'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86',
 'files':[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}for p in sorted(release.iterdir())]}
(release/'G119-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=w/'private/G119-preflight.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for p in sorted(release.iterdir()):z.write(p,p.name)
x={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle.read_bytes()),'release_manifest_sha256':sha((release/'G119-release.json').read_bytes()),'files':len(manifest['files'])+1,'native_phone_operations':0}
(w/'private/release-package.json').write_text(json.dumps(x,indent=2)+'\n')
print(json.dumps(x))
