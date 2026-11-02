"""Package the audited G133 temporary boot; no device operation."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
audit=json.loads((w/'private/image-audit.json').read_text());assert audit['passed']and not audit['unexpected']
test=json.loads((w/'private/footprint-model-02/tests.json').read_text());assert test['passed']and test['cases']==60
assert '\nPASS\n'in(w/'private/report-reader-tests.txt').read_text()
release=w/'private/release';assert not release.exists();release.mkdir()
for src in [w/'private/boot-G133-metadata.img',w/'private/G133-read-report.exe',w.parent/'charging-G128/private/G128-read-report.exe',w.parent/'charging-G132/private/G132-capture-G131-report.exe',w/'Boot-G133-Metadata.ps1']:
 shutil.copy2(src,release/src.name)
(release/'Boot-G133-Metadata.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G133-Metadata.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text('''G133: copied HOB bounds and SCM slot maps, with unchanged G128 metadata

Temporary boot only. Mode16 continues to Windows automatically. It retains the
verified source files, protected adsp_ro access, original metadata/CPU helpers,
file/read budget and cleanup. No PAS request or DSP/charging configuration.

The G133 collector binds the copied HOB traversal to its BootServicesData mapping,
records the PHIT absolute fields as historical values, and requires a bounded
end HOB. It also queries GCD/EFI mappings for the SCM callback slot. It does not
read the callback/table contents, write a hook, change memory reservations or
access candidate staging RAM. Original G128 metadata helpers still allocate,
change CPU cache/MMU mappings and clean up their buffers; this combined mode is
not a wholly hardware-read-only probe. Query completion is not memory/DMA
ownership, CPU permission or an authorization to install a hook or start a DSP.

G133-read-report.exe reads OAPF and requires the new G133 copy/slot context.
The unchanged G128-read-report.exe reads OPAS. Retrieve both before restarting.
G132-capture-G131-report.exe is the unchanged bounded raw OAPF capture; despite
its historical filename it accepts the shared G119PFLT header used by this boot.
Its source and exact identity are retained under the G132 experiment.

Only OnePlus Open DEVICE_SERIAL / kalama, bootloader fastboot, slot a. The launch
script repeats all file hashes and exact device checks. No flash command.
Normal restart returns to installed G80 firmware and default recovery WinPE.
No recording is needed. If a command times out, inspect that run; do not repeat
an uncertain boot. -VerifyOnly performs zero phone commands. Request fastboot
only when ready to launch immediately. Never flash/format/repair modem_a or D:.
''')
manifest={'campaign':'G133','action':'temporary_boot','DSP_start':'not_armed','image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86','files':[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(release.iterdir())]}
(release/'G133-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=w/'private/G133-metadata.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for p in sorted(release.iterdir()):z.write(p,p.name)
r={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle),'release_manifest_sha256':sha(release/'G133-release.json'),'files':len(manifest['files'])+1,'native_phone_operations':0}
(w/'private/release-package.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
