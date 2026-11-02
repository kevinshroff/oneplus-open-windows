"""Retain/decompress/audit the RAM trial and create fixed-file forward/undo plans."""
from pathlib import Path
import base64, hashlib, json, re, subprocess

W = Path(__file__).resolve().parent
P = W / 'private'
s = json.loads((W / 'WIM-build-state.json').read_text())
assert s['phase'] == 'verified_VM_native_trial'
assert all(c['exit_code'] == 0 for c in s['commands'])
dest = P / Path(s['target']).name
def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()
copy_code = '''from pathlib import Path
import hashlib,os,shutil,sys
a,b,h=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert digest(a)==h
with a.open('rb') as f,b.open('xb') as g:
 shutil.copyfileobj(f,g,8*1024*1024);g.flush();os.fsync(g.fileno())
assert digest(b)==h
'''
if not dest.exists():
    subprocess.run(['colima', 'ssh', '--', 'python3', '-c', copy_code, s['target'], str(dest), s['sha256']], check=True)
# A completed, hash-identical copy can be resumed after a local audit error.
# A partial/mismatched copy is preserved and refused, never overwritten.
assert dest.stat().st_size == s['bytes'] and digest(dest) == s['sha256']
with (P / ('verify-retained-' + dest.stem + '.log')).open('xb') as log:
    subprocess.run(['colima', 'ssh', '--', 'wimlib-imagex', 'verify', str(dest)], stdout=log, stderr=subprocess.STDOUT, check=True)
raw = subprocess.check_output(['colima', 'ssh', '--', 'wimlib-imagex', 'dir', str(dest), '1', '--detailed'])
(P / (dest.stem + '-detailed-dir.txt')).write_bytes(raw)
def manifest(raw):
    result = {}
    for block in re.split(r'(?m)^Full Path\s*=\s*', raw)[1:]:
        first, _, body = block.partition('\n')
        assert first[0] == first[-1] == '"'
        key = first[1:-1].replace('\\', '/').strip('/')
        assert key not in result
        streams = []
        for m in re.finditer(r'(?m)^Hash\s*=\s*0x([0-9a-fA-F]{40})\s*\nUncompressed size\s*=\s*(\d+) bytes', body):
            header = [x.strip() for x in body[:m.start()].splitlines() if 'data stream' in x.lower()][-1]
            streams.append({'stream': header, 'sha1': m[1].lower(), 'bytes': int(m[2])})
        assert len(streams) == len(re.findall(r'(?m)^Hash\s*=', body))
        attr = re.search(r'(?m)^Attributes\s*=\s*(0x[0-9a-fA-F]+)', body)
        sec = re.search(r'(?m)^Security Descriptor\s*=\s*([^\n]*)', body)
        result[key] = {'streams': sorted(streams, key=lambda x: x['stream']),
                       'attributes': attr[1] if attr else None, 'security_descriptor': sec[1] if sec else None}
    return result
old = manifest((W.parent / 'gpio-G22/private/G22-gpio-lifecycle-v2-detailed-dir.txt').read_text())
new = manifest(raw.decode())
assert old.keys() == new.keys()
changed = [k for k in old if old[k] != new[k]]
assert sorted(changed) == sorted(s['changed_paths']), changed
for i, path in enumerate(s['changed_paths']):
    expected = (P / ('acpitabl.dat' if i == 0 else 'G23-qcgpio-development.sys')).read_bytes()
    assert new[path]['streams'] == [{'stream': 'Unnamed data stream:', 'sha1': hashlib.sha1(expected).hexdigest(), 'bytes': len(expected)}]
    assert old[path]['attributes'] == new[path]['attributes'] and old[path]['security_descriptor'] == new[path]['security_descriptor']
    extracted = subprocess.check_output(['colima', 'ssh', '--', 'wimlib-imagex', 'extract', str(dest), '1', path, '--to-stdout'])
    assert extracted == expected
info = subprocess.check_output(['colima', 'ssh', '--', 'wimlib-imagex', 'info', str(dest)], text=True)
assert re.search(r'Boot Index:\s+1\b', info)
(P / 'G23-logical-manifest.json').write_text(json.dumps(new, indent=2) + '\n')
source = W.parent / 'gpio-G22/private/G22-gpio-lifecycle-v2.wim'
assert digest(source) == s['source_sha256']
before_n, after_n = source.stat().st_size, dest.stat().st_size
assert after_n >= before_n
changes = []
with source.open('rb') as a, dest.open('rb') as b:
    for off in range(0, before_n, 65536):
        x = a.read(min(65536, before_n - off))
        y = b.read(len(x))
        if x != y:
            changes.append({'offset': off, 'before': base64.b64encode(x).decode(), 'after': base64.b64encode(y).decode()})
    tail = b.read()
assert len(tail) == after_n - before_n
plan = {'version': 'G21-trial-wim-v1', 'name': 'G20-acpi-canary.wim',
        'before_bytes': before_n, 'after_bytes': after_n, 'before_sha256': s['source_sha256'],
        'after_sha256': s['sha256'], 'changes': changes, 'tail': base64.b64encode(tail).decode()}
inverse = dict(plan, before_bytes=after_n, after_bytes=before_n, before_sha256=s['sha256'],
               after_sha256=s['source_sha256'], changes=[dict(c, before=c['after'], after=c['before']) for c in changes])
for name, data in [('G23-wim-forward.json', plan), ('G23-wim-inverse.json', inverse)]:
    path = P / name
    assert not path.exists()
    path.write_text(json.dumps(data, separators=(',', ':')) + '\n')
    assert path.stat().st_size < 16 * 1024 * 1024
r = {'phase': 'retained_verified_audited_trial_and_delta', 'image': str(dest),
     'bytes': after_n, 'sha256': s['sha256'], 'source_sha256': s['source_sha256'],
     'path_entries': len(new), 'only_changed_paths': changed, 'no_added_or_removed_paths': True,
     'changed_path_ACLs_and_attributes_preserved': True, 'compressed_resources_verified': True,
     'exact_table_extracted_G22_driver_unchanged': True, 'boot_index': 1,
     'delta_ranges': len(changes), 'appended_bytes': len(tail),
     'forward_plan_bytes': (P / 'G23-wim-forward.json').stat().st_size,
     'driver_is_unsigned_development_fix': True,
     'metadata_repair_receipt': 'not needed; unchanged driver aliases retain G22 metadata',
     'scope': 'One fixed inactive regular WIM; no raw super/boot/GPT writes.'}
(W / 'WIM-qualified.json').write_text(json.dumps(r, indent=2) + '\n')
print(json.dumps(r, indent=2), flush=True)
