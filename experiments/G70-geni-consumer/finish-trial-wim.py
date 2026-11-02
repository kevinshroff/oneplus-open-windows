"""Audit every WIM entry and real security descriptor; retain exact two-way delta."""
from pathlib import Path
import base64,hashlib,json,re,subprocess

W=Path(__file__).resolve().parent;P=W/'private'
s=json.loads((W/'WIM-build-state.json').read_text())
assert s['phase']=='Mac_retained_trial_copy_matches_VM_full_hash'
source=Path(s['source']);dest=Path(s['retained_target'])
table=W/'private/acpi-01/acpitabl.dat'
def digest(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
assert digest(source)==s['source_sha256'] and digest(dest)==s['sha256']
assert all(c['exit_code']==0 for c in s['commands'])
def manifest(p):
 raw=subprocess.check_output([str(P/'wim-manifest'),str(p)])
 rows={}
 for line in raw.decode('ascii').splitlines():
  fields=line.split('\t');path=bytes.fromhex(fields[0]).decode('utf-8').replace('\\','/').strip('/')
  assert path not in rows and len(fields)>=13
  rows[path]=fields[1:]
 return rows,hashlib.sha256(raw).hexdigest()
old,old_sha=manifest(source);new,new_sha=manifest(dest)
assert len(old)==len(new)==21760 and old.keys()==new.keys()
renumbered=sum(old[k][4]!=new[k][4] for k in old)
def normalize_link_groups(rows):
 groups={}
 for path,v in rows.items():
  if int(v[3])>1:
   assert int(v[4])!=0
   groups.setdefault(v[4],[]).append(path)
 for members in groups.values():
  members.sort();assert all(int(rows[k][3])==len(members)for k in members)
  canonical=hashlib.sha256(json.dumps(members,separators=(',',':')).encode()).hexdigest()
  for k in members:rows[k][4]=canonical
 return sorted(sorted(v) for v in groups.values())
assert normalize_link_groups(old)==normalize_link_groups(new)
changed=[k for k in old if old[k]!=new[k]]
assert changed==['Windows/System32/acpitabl.dat'],{'changed_count':len(changed),'first_paths':changed[:3]}
# Field5 of values is the complete SECURITY_DESCRIPTOR_RELATIVE hex blob.
assert all(old[k][5]==new[k][5] for k in old)
assert all(old[k][1:5]==new[k][1:5] for k in old)
key=changed[0];data=table.read_bytes()
assert new[key][11:]==[':'+hashlib.sha1(data).hexdigest()+':768']
assert subprocess.check_output(['wimlib-imagex','extract',str(dest),'1',key,'--to-stdout'])==data
for path in [source,dest]:
 info=subprocess.check_output(['wimlib-imagex','info',str(path)],text=True)
 assert re.search(r'Boot Index:\s+1\b',info)
with source.open('rb')as a,dest.open('rb')as b:
 x,y=a.read(208),b.read(208)
 assert x[:48]==y[:48] and x[120:124]==y[120:124]==b'\x01\x00\x00\x00'
before_n,after_n=source.stat().st_size,dest.stat().st_size
assert after_n>=before_n
changes=[]
with source.open('rb')as a,dest.open('rb')as b:
 for off in range(0,before_n,65536):
  x=a.read(min(65536,before_n-off));y=b.read(len(x))
  if x!=y:changes.append({'offset':off,'before':base64.b64encode(x).decode(),'after':base64.b64encode(y).decode()})
 tail=b.read()
assert len(tail)==after_n-before_n
plan={'version':'G21-trial-wim-v1','name':'G20-acpi-canary.wim','before_bytes':before_n,'after_bytes':after_n,'before_sha256':s['source_sha256'],'after_sha256':s['sha256'],'changes':changes,'tail':base64.b64encode(tail).decode()}
inverse=dict(plan,before_bytes=after_n,after_bytes=before_n,before_sha256=s['sha256'],after_sha256=s['source_sha256'],changes=[dict(c,before=c['after'],after=c['before'])for c in changes])
for start,expected,p in [(source,dest,plan),(dest,source,inverse)]:
 buf=bytearray(start.read_bytes())
 for c in p['changes']:
  x,y=base64.b64decode(c['before']),base64.b64decode(c['after']);o=c['offset']
  assert buf[o:o+len(x)]==x;buf[o:o+len(x)]=y
 if p['after_bytes']>len(buf):buf.extend(base64.b64decode(p['tail']))
 else:del buf[p['after_bytes']:]
 assert len(buf)==p['after_bytes'] and hashlib.sha256(buf).hexdigest()==digest(expected)
for name,p in [('G70-wim-forward.json',plan),('G70-wim-inverse.json',inverse)]:
 path=P/name;encoded=(json.dumps(p,separators=(',',':'))+'\n').encode()
 assert len(encoded)<16*1024*1024
 if path.exists():assert path.read_bytes()==encoded
 else:
  with path.open('xb')as f:f.write(encoded)
r={'phase':'retained_verified_audited_trial_and_delta','image':str(dest),'bytes':after_n,'sha256':s['sha256'],'source_sha256':s['source_sha256'],'path_entries':len(new),'only_changed_paths':changed,'no_added_or_removed_paths':True,'all_actual_security_descriptors_identical':True,'nonempty_security_descriptors':sum(bool(v[5])for v in new.values()),'all_attributes_and_link_memberships_identical':True,'renumbered_internal_link_IDs':renumbered,'link_ID_comparison':'actual groups of paths and all link counts identical; numerical WIM inode IDs are renumbered on append','table_metadata_before':old[key],'table_metadata_after':new[key],'source_manifest_sha256':old_sha,'trial_manifest_sha256':new_sha,'manifest_API_header_sha256':digest(Path('/opt/homebrew/include/wimlib.h')),'manifest_tool_source_sha256':digest(W/'wim-manifest.c'),'exact_table_extracted':True,'boot_index':1,'header_identity_flags_compression_unchanged':True,'delta_ranges':len(changes),'appended_bytes':len(tail),'forward_plan_bytes':(P/'G70-wim-forward.json').stat().st_size,'forward_plan_sha256':digest(P/'G70-wim-forward.json'),'inverse_plan_sha256':digest(P/'G70-wim-inverse.json'),'both_directions_locally_reconstructed':True,'phone_operations':0}
(W/'WIM-qualified.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:r[k]for k in ['phase','bytes','sha256','path_entries','nonempty_security_descriptors','delta_ranges','appended_bytes','forward_plan_bytes']}),flush=True)
