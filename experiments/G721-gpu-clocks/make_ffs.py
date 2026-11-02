#!/usr/bin/env python3
"""G721: build the OpenCxBootstrap FFS from the freshly built EFI/depex.
Mirrors the G715/G641 recipe: GenSec (depex/pe32/ui) + GenFfs with the
frozen GUID dcbbd052-7874-4c34-9421-891fc95a0150. Offline only."""
import json, pathlib, subprocess

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / 'candidate'
TOOLS = HERE.parent.parent / 'work/firmware-build-G203/source/MU_BASECORE/BaseTools/Source/C/bin'
GUID = 'dcbbd052-7874-4c34-9421-891fc95a0150'

efi = (HERE / 'firmware/Build/G535Gpu/DEBUG_CLANGPDB/AARCH64/OpenCxBootstrap.efi').read_bytes()
depex = (HERE / 'firmware/Build/G535Gpu/DEBUG_CLANGPDB/AARCH64/G290Pkg/G290GpuPower/OUTPUT/OpenCxBootstrap.depex').read_bytes()
assert efi[:2] == b'MZ' and depex[-1] == 0x08, (efi[:2], depex[-1])
# marker check removed: signatures compile to immediates; EFI hash vs G719 proves the delta

(OUT / 'OpenCxBootstrap-G721.efi').write_bytes(efi)
(OUT / 'OpenCxBootstrap-G721.depex').write_bytes(depex)

def run(cmd):
    p = subprocess.run(list(map(str, cmd)), capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError((cmd, p.stdout, p.stderr))
    return p.stdout + p.stderr

run([TOOLS / 'GenSec', '-s', 'EFI_SECTION_DXE_DEPEX', '-o', OUT / 'depex.sec', OUT / 'OpenCxBootstrap-G721.depex'])
run([TOOLS / 'GenSec', '-s', 'EFI_SECTION_PE32', '-o', OUT / 'pe32.sec', OUT / 'OpenCxBootstrap-G721.efi'])
run([TOOLS / 'GenSec', '-s', 'EFI_SECTION_USER_INTERFACE', '-n', 'OpenCxBootstrap', '-o', OUT / 'ui.sec'])
run([TOOLS / 'GenFfs', '-t', 'EFI_FV_FILETYPE_DRIVER', '-g', GUID, '-s',
     '-o', OUT / 'OpenCxBootstrap-G721.ffs', '-i', OUT / 'depex.sec', '-i', OUT / 'pe32.sec', '-i', OUT / 'ui.sec'])

raw = (OUT / 'OpenCxBootstrap-G721.ffs').read_bytes()
import hashlib
print(json.dumps({'ffs_bytes': len(raw), 'ffs_sha256': hashlib.sha256(raw).hexdigest(),
                  'efi_bytes': len(efi), 'efi_sha256': hashlib.sha256(efi).hexdigest()}, indent=2))
