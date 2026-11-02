"""Inspect the hash-bound official archive without executing its installer.

Only the six named INF/KMD/base-config members are extracted. No driver is
installed. Requires pefile; output must be a new directory.
"""
import argparse, hashlib, io, json, struct, zipfile
from pathlib import Path
import pefile

class Slice(io.RawIOBase):
    def __init__(self, f, start, length):
        self.f, self.start, self.length, self.pos = f, start, length, 0
    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos
    def seek(self, offset, whence=0):
        n = offset if whence == 0 else self.pos + offset if whence == 1 else self.length + offset
        if n < 0 or n > self.length: raise ValueError('slice seek')
        self.pos = n
        return n
    def read(self, n=-1):
        n = self.length-self.pos if n < 0 else min(n, self.length-self.pos)
        self.f.seek(self.start+self.pos)
        b = self.f.read(n)
        self.pos += len(b)
        return b

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--archive', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert sha(a.archive) == 'b26cac701a55f70274baaa687754366dcdd97b60a007d6e3acd2eb2a8cc939ab'
a.output.mkdir(exist_ok=False)
installer = a.output/'installer.exe'
with zipfile.ZipFile(a.archive) as z:
    names = [n for n in z.namelist() if n.endswith('Qualcomm_Adreno_Driver-v2026.08.3.exe')]
    assert len(names) == 1
    with z.open(names[0]) as src, installer.open('xb') as dst:
        for b in iter(lambda: src.read(1 << 20), b''): dst.write(b)
pe = pefile.PE(str(installer), fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
resources = []
for kind in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if kind.id != 10: continue
    for entry in kind.directory.entries:
        if entry.id != 104: continue
        for lang in entry.directory.entries:
            d = lang.data.struct
            resources.append((pe.get_offset_from_rva(d.OffsetToData), d.Size))
assert len(resources) == 1
offset, length = resources[0]
assert 0 <= offset < installer.stat().st_size and 0 < length <= installer.stat().st_size-offset
report = {'archive_sha256': sha(a.archive), 'installer_sha256': sha(installer),
          'resource_offset': offset, 'resource_bytes': length, 'installer_executed': False,
          'selected': [], 'configuration': None}
wanted = {'qcdx8380.inf', 'qcdx8480.inf', 'qcdxkm8380.sys', 'qcdxkm8480.sys',
          'qcdxkmbase8380.bin', 'qcdxkmbase8380_pa.bin'}
with installer.open('rb') as f, zipfile.ZipFile(Slice(f, offset, length)) as z:
    for name in sorted(z.namelist()):
        base = name.replace('\\', '/').split('/')[-1]
        if base not in wanted: continue
        target = a.output/base
        assert not target.exists()
        b = z.read(name)  # ZipFile verifies the member CRC.
        target.write_bytes(b)
        report['selected'].append({'member': name, 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()})
assert {Path(x['member'].replace('\\', '/')).name for x in report['selected']} == wanted
b = (a.output/'qcdxkmbase8380.bin').read_bytes()
header, magic, version, count, stride = struct.unpack_from('<5I', b)
assert (magic, version, count, stride, header) == (0x80807070, 1, 12, 12, 52)
sections, previous = [], header+count*stride
for i in range(count):
    tag, start, size = struct.unpack_from('<4sII', b, header+i*stride)
    assert start == previous and start+size <= len(b)
    sections.append({'tag': tag.decode('ascii'), 'offset': start, 'bytes': size,
                     'sha256': hashlib.sha256(b[start:start+size]).hexdigest()})
    previous = start+size
assert previous == len(b)
report['configuration'] = {'name': b[20:52].split(b'\0')[0].decode('ascii'), 'sections': sections,
                           'limits': 'Container structure only; settings semantics and SM8550 suitability are unqualified.'}
(a.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({'members': len(report['selected']), 'sections': len(sections), 'installer_executed': False}))
