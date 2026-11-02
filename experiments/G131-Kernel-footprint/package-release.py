"""Assemble the audited temporary-boot package. No phone or host operation."""
from pathlib import Path
import hashlib,json,shutil,zipfile
w=Path(__file__).resolve().parent
audit=json.loads((w/'private/image-audit.json').read_text())
assert audit['passed']and audit['unexpected']==[]
assert json.loads((w/'private/preflight-test-results.json').read_text())['passed']
assert json.loads((w.parent/'charging-G128/private/native-probe-model-03/tests.json').read_text())['passed']
assert json.loads((w/'private/footprint-model-02/tests.json').read_text())['passed']
tests=(w/'private/report-reader-tests.txt').read_text()
assert '\nPASS\n'in tests and '\nFAIL'not in tests
release=w/'private/release'
assert not release.exists()
release.mkdir()
for src in [w/'private/boot-G131-metadata.img',w/'private/G131-read-report.exe',w.parent/'charging-G128/private/G128-read-report.exe',w/'Boot-G131-Metadata.ps1']:
 shutil.copy2(src,release/src.name)
(release/'Boot-G131-Metadata.cmd').write_bytes(b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G131-Metadata.ps1"\r\nexit /b %errorlevel%\r\n')
(release/'README.txt').write_text("G131: combined read-only footprint and original PIL metadata diagnostic\n\nTemporary boot only; mode16 continues to Windows automatically.\nRetains G128 original-code/config checks and metadata/CPU-only ELF helpers,\nthe G119 protected adsp_ro view, exact files, read budget and cleanup.\nOPAS keeps the G128META ABI and is read by the unchanged G128-read-report.exe.\n\nAdds a bounded OAPF report of the proposed A9F80000..AE880000 staging span:\nstatic Kernel descriptor, GCD and EFI memory maps, HOB allocation/FV overlaps,\nloaded images and known firmware object pointers. G131-read-report.exe reads\nOAPF, checks the fixed DSDT identity and all report identity/size/checksum guards.\nBoth readers must be used after boot. Query completion and absence of listed\noverlaps do not prove ownership, DMA safety or secure firmware acceptance.\nThe reader always reports kernel_memory_eligible=false.\n\nNo target staging memory read/write, memory-map or reservation changes,\npublic PIL Load, PAS, DSP start/shutdown, SCM hook or charger configuration.\nThe existing metadata helper's heap/cache/MMU allocation paths still run.\nThis is not a hardware qualification of DSP or charging.\n\nOnly verified OnePlus Open DEVICE_SERIAL / kalama, bootloader fastboot, slot a.\nNo partition flash command. A normal restart uses installed G80 firmware and\ndefault WinPE recovery. No recording is needed initially. Do not restart old\nflashing watchers. Launch repeats all file hashes and exact device checks.\nIf a command times out, inspect that run instead of submitting it again.\nBoot-G131-Metadata.ps1 -VerifyOnly uses no phone commands.\nA low battery needs a working power source before any boot test.\nIf temporary boot stalls, physical force-restart returns to installed firmware.\nNever flash, format or repair modem_a / D:.\n")

sha=lambda b:hashlib.sha256(b).hexdigest()
manifest={'campaign':'G131','action':'temporary_boot','DSP_start':'not_armed',
 'image_sha256':audit['image_sha256'],'FD_sha256':audit['FD_sha256'],
 'fastboot_sha256':'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86',
 'files':[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}for p in sorted(release.iterdir())]}
(release/'G131-release.json').write_text(json.dumps(manifest,indent=2)+'\n')
bundle=w/'private/G131-metadata.zip'
with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED,compresslevel=1)as z:
 for p in sorted(release.iterdir()):z.write(p,p.name)
x={'zip_bytes':bundle.stat().st_size,'zip_sha256':sha(bundle.read_bytes()),'release_manifest_sha256':sha((release/'G131-release.json').read_bytes()),'files':len(manifest['files'])+1,'native_phone_operations':0}
(w/'private/release-package.json').write_text(json.dumps(x,indent=2)+'\n')
print(json.dumps(x))
