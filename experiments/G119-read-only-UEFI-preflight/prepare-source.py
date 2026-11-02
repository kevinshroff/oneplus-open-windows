"""Prepare a separate, hash-bound UEFI preflight source candidate. No deployment."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import uuid
import argparse

w = Path(__file__).resolve().parent
capture = w.parent / 'charging-G118/private/firmware-input'
manifest_bytes = (capture / 'capture.json').read_bytes()
m = json.loads(manifest_bytes)
sha = lambda b: hashlib.sha256(b).hexdigest()
assert m['native_source_writes'] == 0 and m['FAT_metadata_unchanged'] and m['GPT_copies_revalidated']
assert m['source_directory'] == 'image' and len(m['files']) == 64 and len(m['metadata']) == 6
assert m['target']['Bytes'] == 314572800 and m['target']['Offset'] == 18898944
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=w/'private/candidate-source')
args = parser.parse_args()
out = args.output.resolve()
assert not out.exists()
out.mkdir()
lib = Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
device = Path('Platforms/KailuaPkg/Device/oneplus-open')

for p in [lib/'DeviceBootManagerLib.c', lib/'DeviceBootManagerLib.inf', lib/'OpenBringupDiagnostics.c',
          device/'PcdsFixedAtBuild.dsc.inc']:
    src = w/'private/baseline'/p
    dest = out/p
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)

reservation = w.parent/'charging-G117/private/reservation-candidate-01/candidate-source'
for rel in ['Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c', 'Binaries/RawFiles/uefiplat.cfg', 'Binaries/RawFiles/uefipil.cfg']:
    p = device/rel
    dest = out/p
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(reservation/p, dest)

p = out/device/'Binaries/RawFiles/uefipil.cfg'
s = p.read_text()
s, changed = re.subn(r'^PartiLabel = modem_a$', 'PartiLabel = adsp_ro', s, flags=re.MULTILINE)
assert changed == 2
# PILDxe still receives no automatic request. A future explicit request would
# select only the source-bound read-only facade, never a generic Basic Data GUID.
assert '[AUTO]' in s
p.write_text(s)

p = out/device/'PcdsFixedAtBuild.dsc.inc'
s = p.read_text()
assert s.count('PcdOpenBringupMode|9') == 1
p.write_text(s.replace('PcdOpenBringupMode|9', 'PcdOpenBringupMode|15'))
p = out/lib/'DeviceBootManagerLib.inf'
s = p.read_text()
assert s.count('  OpenBringupDiagnostics.c') == 1
p.write_text(s.replace('  OpenBringupDiagnostics.c', '  OpenBringupDiagnostics.c\n  OpenAdspPreflight.c'))
p = out/lib/'DeviceBootManagerLib.c'
s = p.read_text()
old = '        (FixedPcdGet32 (PcdOpenBringupMode) != 11)) {'
assert s.count(old) == 1
p.write_text(s.replace(old, '        (FixedPcdGet32 (PcdOpenBringupMode) != 11) &&\n        (FixedPcdGet32 (PcdOpenBringupMode) != 15)) {'))
p = out/lib/'OpenBringupDiagnostics.c'
s = p.read_text()
s = s.replace('VOID OpenRunBootRepairUsb (VOID);', 'VOID OpenRunBootRepairUsb (VOID);\nEFI_STATUS OpenRunAdspPreflight (VOID);')
old = '    if (FixedPcdGet32 (PcdOpenBringupMode) >= 7) {'
assert s.count(old) == 1
s = s.replace(old, '    if (FixedPcdGet32 (PcdOpenBringupMode) == 15) {\n      { EFI_STATUS ReportStatus = OpenRunAdspPreflight ();\n        DEBUG ((DEBUG_ERROR, "G119 report publication: %r\\n", ReportStatus)); }\n      // ACPI carries the preflight report; continue without timed photo pages.\n      if (ContinueWindows) { FreePool (mReport); mReport = NULL; return; }\n    } else if (FixedPcdGet32 (PcdOpenBringupMode) >= 7) {')
p.write_text(s)

def c_bytes(h):
    return '{' + ','.join('0x'+h[i:i+2] for i in range(0, len(h), 2)) + '}'

def c_guid(text):
    g = uuid.UUID(text)
    return '{0x%08x,0x%04x,0x%04x,%s}' % (g.time_low, g.time_mid, g.time_hi_version, c_bytes(g.bytes[8:].hex()))

header = ['/* G119: generated from the exact G118 capture; contains no firmware payload. */',
          '#define OPEN_ADSP_INPUT_SHA256 "'+sha(manifest_bytes)+'"',
          'typedef struct { CONST CHAR8 *Name; UINT64 Bytes; UINT8 Hash[32]; } OPEN_ADSP_FILE;',
          'typedef struct { UINT64 Offset; UINTN Bytes; UINT8 Hash[32]; } OPEN_ADSP_METADATA;',
          'STATIC CONST EFI_GUID mSourcePartitionGuid = '+c_guid(m['target']['PartitionGUID'])+';',
          'STATIC CONST EFI_GUID mBasicDataGuid = '+c_guid(m['target']['TypeGUID'])+';',
          'STATIC CONST UINT8 mSourceHeaderHash[32] = '+c_bytes(m['GPT_header_sha256'])+';',
          'STATIC CONST UINT8 mSourceArrayHash[32] = '+c_bytes(m['GPT_array_sha256'])+';',
          'STATIC CONST OPEN_ADSP_FILE mAdspFiles[] = {']
for row in m['files']:
    data = (capture/'firmware/image'/row['Name']).read_bytes()
    assert len(data) == row['Bytes'] and sha(data) == row['SHA256']
    assert sum(n for off,n in row['Extents']) == len(data)
    assert all(0 <= off < m['target']['Bytes'] and 0 < n <= m['target']['Bytes']-off for off,n in row['Extents'])
    header.append('  {"%s", %dULL, %s},' % (row['Name'], row['Bytes'], c_bytes(row['SHA256'])))
header += ['};', 'STATIC CONST OPEN_ADSP_METADATA mAdspMetadata[] = {']
for row in m['metadata']:
    data = (capture/row['name']).read_bytes()
    assert len(data) == row['bytes'] and sha(data) == row['sha256']
    header.append('  {%dULL, %dU, %s},' % (row['offset'], row['bytes'], c_bytes(row['sha256'])))
header += ['};', '']
(out/lib/'OpenAdspInputs.h').write_text('\n'.join(header))
shutil.copy2(w/'OpenAdspPreflight.c', out/lib/'OpenAdspPreflight.c')
hashes = {str(p.relative_to(out)): sha(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()}
(w/'private'/f'{out.name}-hashes.json').write_text(json.dumps(hashes, indent=2)+'\n')
print(json.dumps({'candidate_files': len(hashes), 'input_manifest_sha256': sha(manifest_bytes),
                  'firmware_files': len(m['files']), 'AUTO': 'empty', 'native_operations': 0}))
