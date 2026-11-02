"""Retain and fully audit the one-table image; prepare fixed-file undoable deltas."""
from pathlib import Path
import base64, hashlib, json, re, subprocess

W = Path(__file__).resolve().parent
P = W / 'private'
s = json.loads((W / 'WIM-build-state.json').read_text())
assert s['phase'] == 'VM_native_G63_table_trial_verified_not_deployed'
assert all(c['exit_code'] == 0 for c in s['commands'])
dest = P / Path(s['target']).name
source = Path(s['retained_source'])
table = W.parent / 'resources-G63/private/acpi-02/acpitabl.dat'

def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()

assert digest(source) == s['source_sha256']
assert digest(table) == 'cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece'
copy_code = '''from pathlib import Path
import hashlib,os,shutil,sys
a,b,h=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
def digest(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert digest(a)==h
with a.open('rb')as f,b.open('xb')as g:
 shutil.copyfileobj(f,g,8*1024*1024);g.flush();os.fsync(g.fileno())
assert digest(b)==h
'''
if not dest.exists():
    subprocess.run(['colima','ssh','--','python3','-c',copy_code,s['target'],str(dest),s['sha256']],check=True)
assert dest.stat().st_size == s['bytes'] and digest(dest) == s['sha256']
log = P / 'verify-retained.log'
if not log.exists():
    with log.open('xb') as f:
        subprocess.run(['colima','ssh','--','wimlib-imagex','verify',str(dest)],stdout=f,stderr=subprocess.STDOUT,check=True)
assert b'ERROR' not in log.read_bytes()

def detailed(path, name):
    local = P / name
    if not local.exists():
        raw = subprocess.check_output(['colima','ssh','--','wimlib-imagex','dir',str(path),'1','--detailed'])
        with local.open('xb') as f:
            f.write(raw)
    return local.read_text()

def manifest(raw):
    result = {}
    for block in re.split(r'(?m)^Full Path\s*=\s*',raw)[1:]:
        first,_,body = block.partition('\n')
        assert first[0] == first[-1] == '"'
        key = first[1:-1].replace('\\','/').strip('/')
        assert key not in result
        streams = []
        for m in re.finditer(r'(?m)^Hash\s*=\s*0x([0-9a-fA-F]{40})\s*\nUncompressed size\s*=\s*(\d+) bytes',body):
            header = [x.strip() for x in body[:m.start()].splitlines() if 'data stream' in x.lower()][-1]
            streams.append({'stream':header,'sha1':m[1].lower(),'bytes':int(m[2])})
        assert len(streams) == len(re.findall(r'(?m)^Hash\s*=',body))
        attr = re.search(r'(?m)^Attributes\s*=\s*(0x[0-9a-fA-F]+)',body)
        sec = re.search(r'(?m)^Security Descriptor\s*=\s*([^\n]*)',body)
        result[key] = {'streams':sorted(streams,key=lambda x:x['stream']),
                       'attributes':attr[1] if attr else None,'security_descriptor':sec[1] if sec else None}
    return result

old = manifest(detailed(source,'source-detailed-dir.txt'))
new = manifest(detailed(dest,'trial-detailed-dir.txt'))
assert len(old) == len(new) == 21760
assert old.keys() == new.keys()
changed = [k for k in old if old[k] != new[k]]
assert changed == ['Windows/System32/acpitabl.dat'], changed
for path in changed:
    data = table.read_bytes()
    assert new[path]['streams'] == [{'stream':'Unnamed data stream:','sha1':hashlib.sha1(data).hexdigest(),'bytes':len(data)}]
    assert old[path]['attributes'] == new[path]['attributes'] and old[path]['security_descriptor'] == new[path]['security_descriptor']
    extracted = subprocess.check_output(['colima','ssh','--','wimlib-imagex','extract',str(dest),'1',path,'--to-stdout'])
    assert extracted == data
info = subprocess.check_output(['colima','ssh','--','wimlib-imagex','info',str(dest)],text=True)
assert re.search(r'Boot Index:\s+1\b',info)
assert digest(source) == s['source_sha256'] and digest(dest) == s['sha256']
before_n,after_n = source.stat().st_size,dest.stat().st_size
assert after_n >= before_n
changes = []
with source.open('rb') as a,dest.open('rb') as b:
    for off in range(0,before_n,65536):
        x = a.read(min(65536,before_n-off));y = b.read(len(x))
        if x != y:
            changes.append({'offset':off,'before':base64.b64encode(x).decode(),'after':base64.b64encode(y).decode()})
    tail = b.read()
assert len(tail) == after_n-before_n
plan = {'version':'G21-trial-wim-v1','name':'G20-acpi-canary.wim',
        'before_bytes':before_n,'after_bytes':after_n,'before_sha256':s['source_sha256'],
        'after_sha256':s['sha256'],'changes':changes,'tail':base64.b64encode(tail).decode()}
inverse = dict(plan,before_bytes=after_n,after_bytes=before_n,before_sha256=s['sha256'],after_sha256=s['source_sha256'],
               changes=[dict(c,before=c['after'],after=c['before']) for c in changes])
# Reconstruct both directions independently before exporting a plan.
for start,expected,p in [(source,dest,plan),(dest,source,inverse)]:
    reconstructed = bytearray(start.read_bytes())
    for c in p['changes']:
        x,y = base64.b64decode(c['before']),base64.b64decode(c['after'])
        off = c['offset'];assert reconstructed[off:off+len(x)] == x
        reconstructed[off:off+len(x)] = y
    if p['after_bytes'] > len(reconstructed):
        reconstructed.extend(base64.b64decode(p['tail']))
    else:
        del reconstructed[p['after_bytes']:]
    assert len(reconstructed) == p['after_bytes'] and hashlib.sha256(reconstructed).hexdigest() == digest(expected)
for name,data in [('G64-wim-forward.json',plan),('G64-wim-inverse.json',inverse)]:
    path = P / name
    encoded = (json.dumps(data,separators=(',',':'))+'\n').encode()
    assert len(encoded) < 16*1024*1024
    if path.exists():
        assert path.read_bytes() == encoded
    else:
        with path.open('xb') as f:f.write(encoded)
r = {'phase':'retained_verified_audited_trial_and_delta','image':str(dest),
     'bytes':after_n,'sha256':s['sha256'],'source_sha256':s['source_sha256'],
     'path_entries':len(new),'only_changed_paths':changed,'no_added_or_removed_paths':True,
     'changed_path_ACLs_and_attributes_preserved':True,'compressed_resources_verified':True,
     'exact_table_extracted':True,'boot_index':1,'delta_ranges':len(changes),'appended_bytes':len(tail),
     'forward_plan_bytes':(P/'G64-wim-forward.json').stat().st_size,
     'both_directions_locally_reconstructed':True,'phone_operations':0,
     'scope':'One fixed inactive regular WIM; no raw super/boot/GPT writes.'}
(W/'WIM-qualified.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2),flush=True)
