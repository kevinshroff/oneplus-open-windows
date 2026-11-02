"""Package the audited DTB error diagnostic. No device operation."""
from pathlib import Path
import hashlib
import json
import shutil
import zipfile

w = Path(__file__).resolve().parent
p = w / 'private'
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
a = json.loads((p / 'image-audit.json').read_text())
assert a['passed'] and not a['unexpected']
assert sha(p / 'boot-G136-memory-diagnostic.img') == a['image_sha256']
for name, count in [('adapter-model-01/tests.json', 59),
                    ('memory-observer-model-01/tests.json', 44),
                    ('error-capture-model-03/tests.json', 121),
                    ('original-SCM-log-01.json', 23),
                    ('PIL-filtered-return-original-01.json', 4),
                    ('exact-span-original-02.json', 8),
                    ('preflight-test-results.json', 33)]:
    result = json.loads((p / name).read_text())
    assert result['passed'] and result['cases'] == count, name
assert '\nPASS\n' in (p / 'reader-tests.txt').read_text()
negative = json.loads((p / 'reader-negative-native.json').read_text())
assert negative['passed'] and negative['reader_sha256'] == sha(p / 'G136-read-DSP.exe')
candidate = json.loads((p / 'candidate-source-hashes.json').read_text())
for name, expected in candidate.items():
    assert sha(p / 'candidate-source' / name) == expected, name
linked = json.loads((p / 'linked-sink-audit.json').read_text())
assert linked['passed'] and linked['BDS_sha256'] == sha(p / 'BdsDxe-linked.efi')

release = p / 'release'
assert not release.exists()
release.mkdir()
files = [p / 'boot-G136-memory-diagnostic.img', p / 'G136-read-DSP.exe',
         w.parent / 'charging-G128/private/G128-read-report.exe',
         w.parent / 'charging-G132/private/G132-capture-G131-report.exe',
         w / 'Boot-G136-MemoryDiagnostic.ps1', w / 'Refresh-Existing-Debugger.ps1']
for file in files:
    shutil.copy2(file, release / file.name)
(release / 'Boot-G136-MemoryDiagnostic.cmd').write_bytes(
    b'@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Boot-G136-MemoryDiagnostic.ps1"\r\nexit /b %errorlevel%\r\n')
(release / 'README.txt').write_text('''G136: one-use OEM secure memory-setup error diagnostic

One temporary fastboot boot, without partition flashing. Admission, source
files, memory inventory and current GOP exclusions remain those of G134.
The DTB request remains image36, base A9F80000, size80000. A different ELF span
is not being tested here. No changes to modem_a/D:, INI, FAT, BCD, installed
firmware, touch, 300% scaling, Never timeouts or the retained test certificate.

Only DTB INIT and MEM_SETUP may reach the original SCM API. On an accepted
MEM_SETUP the observer returns EFI_ABORTED to stop the original PIL range
helper before loading payload or entering AUTH. Main image1, AUTH, shutdown
and same-boot retry are refused. Original API status and all four result slots
are recorded separately from the diagnostic filtered return. The OEM service
can affect secure/hardware state or never return; no native success is claimed
by these source models. Keep physical recovery available for this first boot.

For the narrow request window, the SCM driver's cached debug serial pointer
is routed to a bounded RAM sink. The sink captures only the expected numeric
TzStatus/SmcId error text from the live original-call stack. It does not forward
to the unknown serial object. The original SCM/formatter instructions remain
unchanged. Read/Poll report no data. The exact saved serial pointer and original
SCM method are restored, read back and checked with LocateProtocol. Failed
restoration prevents firmware boot continuation while retaining its context.

G136-read-DSP.exe reads the OADP and OSER ACPI tables twice and cross-binds the
original API ledger to the OEM32-bit error text. Full64-bit SMC X0 is not retained
by that format. Stable available raw tables are retained even if decoding fails.
G128-read-report.exe reads pre-request OPAS; the unchanged historical
G132-capture-G131-report.exe reads raw OAPF with G136 diagnostic text. Collect
all four tables on the same fresh boot. These results alone do not establish a
running DSP, GLINK or working charging. No video is needed initially.

The launcher verifies hashes and exact DEVICE_SERIAL/kalama/bootloader/slot-a identity,
refreshes the existing one-shot debugger, rechecks the mode and boots once.
Its debugger guard accepts only the known G134 PID2532/log. VerifyOnly issues
no phone/debugger commands. A normal restart returns to installed G80/default
WinPE. Ask for fastboot only when fully staged and immediately ready.
''')
manifest = {'campaign': 'G136', 'action': 'temporary_boot',
            'DSP_start': 'memory_error_diagnostic',
            'image_sha256': a['image_sha256'], 'FD_sha256': a['FD_sha256'],
            'fastboot_sha256': 'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86',
            'files': [{'name': f.name, 'bytes': f.stat().st_size, 'sha256': sha(f)}
                      for f in sorted(release.iterdir())]}
(release / 'G136-release.json').write_text(json.dumps(manifest, indent=2) + '\n')
bundle = p / 'G136-memory-diagnostic.zip'
with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
    for file in sorted(release.iterdir()):
        archive.write(file, file.name)
result = {'zip_bytes': bundle.stat().st_size, 'zip_sha256': sha(bundle),
          'release_manifest_sha256': sha(release / 'G136-release.json'),
          'entries': len(manifest['files']) + 1, 'native_phone_operations': 0}
(p / 'release-package.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
