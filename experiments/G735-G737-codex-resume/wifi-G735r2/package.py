#!/usr/bin/env python3
"""G735: package the patched WLAN DXE (SMMU identity banks) into FFS GUID
82f10622-a583-4e53-87da-2d41b22aa622 and compose the fix boot image on the
exact frozen G182 base. Offline only."""
import ast, collections, gzip, hashlib, json, lzma, pathlib, struct, subprocess, types, uuid

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / 'candidate'
OUT.mkdir(parents=True, exist_ok=True)
TOOLS = ROOT / 'work/firmware-build-G203/source/MU_BASECORE/BaseTools/Source/C/bin'
def sha(b): return hashlib.sha256(b).hexdigest()
def align(n, a=8): return (n + a - 1) & ~(a - 1)
def run(cmd):
    p = subprocess.run(list(map(str, cmd)), capture_output=True, text=True)
    if p.returncode: raise RuntimeError((cmd, p.stdout[-2000:], p.stderr[-2000:]))
    return p.stdout + p.stderr

inventory_path = ROOT / 'work/charging-G106/inventory-fd.py'
extract_path = ROOT / 'work/charging-G144/audit-image.py'
m = types.ModuleType('g203_retained_inventory')
exec(compile(inventory_path.read_text(), '<retained-inventory>', 'exec'), m.__dict__)
node = next(n for n in ast.parse(extract_path.read_text()).body if isinstance(n, ast.ClassDef) and n.name == 'Extract')
env = {'m': m, 'struct': struct}; exec(compile(ast.Module(body=[node], type_ignores=[]), '<retained-extractor>', 'exec'), env)
class Capture(env['Extract']):
    def __init__(self): super().__init__(); self.blobs = {}
    def volume(self, data, path='FD', depth=0):
        self.blobs[path] = bytes(data); super().volume(data, path, depth)

def all_files(fv):
    length = struct.unpack_from('<Q', fv, 32)[0]; head = struct.unpack_from('<H', fv, 48)[0]
    assert length == len(fv) and sum(struct.unpack('<' + 'H' * (head // 2), fv[:head])) & 65535 == 0
    blocks = []; p = 56
    while True:
        n, size = struct.unpack_from('<II', fv, p); p += 8
        if n == size == 0: break
        assert n and size; blocks.append((n, size))
    assert sum(n * size for n, size in blocks) == length
    erase = 255 if struct.unpack_from('<I', fv, 44)[0] & 0x800 else 0
    rows = []; p = align(head)
    while p < length and not all(v == erase for v in fv[p:]):
        h = 32 if fv[p + 19] & 1 else 24
        n = struct.unpack_from('<Q', fv, p + 24)[0] if h == 32 else int.from_bytes(fv[p + 20:p + 23], 'little')
        assert h <= n <= length - p
        raw = bytes(fv[p:p + n]); assert (sum(raw[:h]) - raw[17] - raw[23]) & 255 == 0
        if raw[19] & 0x40: assert (sum(raw[h:]) + raw[17]) & 255 == 0
        else: assert raw[17] == 0xaa
        rows.append({'offset': p, 'guid': str(uuid.UUID(bytes_le=raw[:16])), 'type': raw[18], 'bytes': n, 'sha256': sha(raw), 'raw': raw})
        p = align(p + n)
    return rows, p, erase, blocks

GUID = '82f10622-a583-4e53-87da-2d41b22aa622'
efi = (HERE / 'firmware/Build/G289Wlan/DEBUG_CLANGPDB/AARCH64/G289Pkg/Wlan/G289Wlan/OUTPUT/WlanBringupG622.efi').read_bytes()
depex = (HERE / 'firmware/Build/G289Wlan/DEBUG_CLANGPDB/AARCH64/G289Pkg/Wlan/G289Wlan/OUTPUT/WlanBringupG622.depex').read_bytes()
assert efi[:2] == b'MZ' and depex[-1] == 0x08
(OUT / 'WlanBringupG735.efi').write_bytes(efi)
(OUT / 'WlanBringupG735.depex').write_bytes(depex)
run([TOOLS / 'GenSec', '-s', 'EFI_SECTION_DXE_DEPEX', '-o', OUT / 'depex.sec', OUT / 'WlanBringupG735.depex'])
run([TOOLS / 'GenSec', '-s', 'EFI_SECTION_PE32', '-o', OUT / 'pe32.sec', OUT / 'WlanBringupG735.efi'])
run([TOOLS / 'GenSec', '-s', 'EFI_SECTION_USER_INTERFACE', '-n', 'WlanBringupG622', '-o', OUT / 'ui.sec'])
run([TOOLS / 'GenFfs', '-t', 'EFI_FV_FILETYPE_DRIVER', '-g', GUID, '-s',
     '-o', OUT / 'WlanG735.ffs', '-i', OUT / 'depex.sec', '-i', OUT / 'pe32.sec', '-i', OUT / 'ui.sec'])
raw = (OUT / 'WlanG735.ffs').read_bytes()
assert str(uuid.UUID(bytes_le=raw[:16])) == GUID and raw[18] == 7 and raw[23] == 7
assert int.from_bytes(raw[20:23], 'little') == len(raw)

# ---- compose onto exact frozen G182 base ----
base_dir = ROOT / 'work/platform-owner-G182/private'
fd = (base_dir / 'G182-resources.fd').read_bytes()
assert sha(fd) == 'e27f5e4f83a73178848aa80ca0ab5fd8efa4c838a68fde35db02abe2803683f8' and len(fd) == 0x400000
image = (base_dir / 'boot-G182-resources.img').read_bytes()
assert sha(image) == 'ccae12adda80fabface9748f646ae17410eb6e18e47e9bc176852f61e1a0cbaf'
base = Capture(); base.volume(fd); base_count = len(base.raw)
assert GUID not in base.raw
inner_path = next(k for k in base.blobs if k != 'FD'); assert len(base.blobs) == 2
old_fv = base.blobs[inner_path]
old_rows, used, erase, blocks = all_files(old_fv)
assert erase == 255 and blocks == [(len(old_fv) // 4096, 4096)]
outer_rows, outer_used, outer_erase, outer_blocks = all_files(fd)
container = '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
parent = next(r for r in outer_rows if r['guid'] == container)
assert parent == outer_rows[-1] and parent['raw'][19] & 1 == 0
stored = bytearray(raw); stored[23] ^= erase
append_at = used
new_length = align(append_at + len(stored), 4096)
assert new_length >= len(old_fv) and new_length < 0xffffff - 8
fv = bytearray(old_fv) + bytearray([erase]) * (new_length - len(old_fv))
fv[append_at:append_at + len(stored)] = stored
struct.pack_into('<Q', fv, 32, new_length); struct.pack_into('<I', fv, 56, new_length // 4096)
struct.pack_into('<H', fv, 50, 0); struct.pack_into('<H', fv, 50, (-sum(struct.unpack('<36H', fv[:72]))) & 65535)
rows, new_used, _, _ = all_files(fv)
assert len(rows) == len(old_rows) + 1 and rows[-1]['guid'] == GUID
for old, newr in zip(old_rows, rows): assert old == newr
allowed = set(range(32, 40)) | {50, 51} | set(range(56, 60))
assert all(a == b or i in allowed for i, (a, b) in enumerate(zip(old_fv[:72], fv[:72])))
r = parent['raw']; h = 24; section = r[h:]
section_size = int.from_bytes(section[:3], 'little')
assert section[3] == 2 and section_size == len(section)
data_offset, attrs = struct.unpack_from('<HH', section, 20); assert data_offset == 24 and attrs == 1
decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 << 20)
expanded = decoder.decompress(section[data_offset:], max_length=32 << 20)
assert decoder.eof and not decoder.unused_data and expanded[7] == 0x17 and expanded[8:] == old_fv
assert int.from_bytes(expanded[4:7], 'little') == len(old_fv) + 4
stream = bytearray(expanded[:8]) + fv; stream[4:7] = (len(fv) + 4).to_bytes(3, 'little')
(OUT / 'FVMAIN-expanded.sections').write_bytes(stream)
log = run([TOOLS / 'LzmaCompress', '-e', '-o', OUT / 'FVMAIN.lzma', OUT / 'FVMAIN-expanded.sections'])
compressed_bytes = (OUT / 'FVMAIN.lzma').read_bytes()
decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 << 20)
check = decoder.decompress(compressed_bytes, max_length=32 << 20)
assert decoder.eof and not decoder.unused_data and check == stream
sec = bytearray(section[:data_offset]) + compressed_bytes; sec[:3] = len(sec).to_bytes(3, 'little')
hdr = bytearray(r[:24]); total = 24 + len(sec); hdr[20:23] = total.to_bytes(3, 'little')
hdr[17] = (-sum(sec)) & 255 if hdr[19] & 0x40 else 0xaa
hdr[16] = 0; hdr[16] = (-(sum(hdr) - hdr[17] - hdr[23])) & 255
new_parent = hdr + sec
candidate = bytearray(fd); candidate[parent['offset']:] = bytes([outer_erase]) * (len(fd) - parent['offset'])
candidate[parent['offset']:parent['offset'] + len(new_parent)] = new_parent
candidate = bytes(candidate)
chk = Capture(); chk.volume(candidate)
assert set(chk.raw) == set(base.raw) | {GUID}
changed = [g for g in base.raw if chk.raw[g] != base.raw[g]]; assert changed == [container], changed
for path, data in chk.blobs.items(): all_files(data)
for g in base.leaves: assert chk.leaves[g] == base.leaves[g]
body = chk.raw[GUID][24:]; sections = {}; pos = 0
while pos < len(body):
    n = int.from_bytes(body[pos:pos + 3], 'little'); kind = body[pos + 3]
    assert 4 <= n <= len(body) - pos
    assert kind not in sections; sections[kind] = body[pos + 4:pos + n]; pos = min(align(pos + n, 4), len(body))
assert sections[0x13] == depex and sections[0x10] == efi

# boot wrap
assert image[:8] == b'ANDROID!' and struct.unpack_from('<I', image, 40)[0] == 3 and struct.unpack_from('<I', image, 12)[0] == 0
old_n = struct.unpack_from('<I', image, 8)[0]
kernel = gzip.decompress(image[4096:4096 + old_n]); assert kernel[112:] == fd
new_kernel = kernel[:112] + candidate; gz = gzip.compress(new_kernel, mtime=0)
header = bytearray(image[:4096]); struct.pack_into('<I', header, 8, len(gz))
boot = bytes(header) + gz
boot += bytes(align(len(boot), 4096) - len(boot))
old_tail = image[align(4096 + old_n, 4096):]; assert not any(old_tail)
assert boot[:8] + bytes(4) + boot[12:4096] == image[:8] + bytes(4) + image[12:4096]
assert gzip.decompress(boot[4096:4096 + len(gz)]) == new_kernel
(OUT / 'boot-G735r2-wifi-smmu-identity.img').write_bytes(boot)
report = {
 'schema': 'g735r2-wifi-smmu-identity-package/1',
 'base_fd_sha256': sha(fd), 'candidate_fd_sha256': sha(candidate),
 'boot_image_sha256': sha(boot), 'boot_image_bytes': len(boot), 'revision': 'r2: SID guard uses verified G403 preparation hash; no live qualification',
 'efi_sha256': sha(efi), 'depex_sha256': sha(depex), 'ffs_sha256': sha(raw),
 'guid': GUID, 'original_members_unchanged': True, 'only_changed_ancestor': container,
 'lzma_roundtrip_passed': True, 'boot_roundtrip_passed': True,
 'fix': 'identity pass-through context banks for PCIe0 streams 0x1400/0x1401 in apps SMMU 0x15000000 (PARF translation retained)',
 'native_tested': False,
}
(HERE / 'evidence').mkdir(exist_ok=True)
(HERE / 'evidence' / 'package-report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
