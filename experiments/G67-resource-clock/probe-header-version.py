"""One metadata-only comparison; this never installs or calls the clock driver."""
from pathlib import Path
import hashlib,json,struct,uuid
import pefile
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('native-header-version-probe.json');s=R.s
old=(P/'G67-client-v3.exe').read_bytes();assert hashlib.sha256(old).hexdigest()=='8e4c392d372c405ecd0c1d738dc2d1b1a2b6757704193bcdeebde441bdc4d94f'
pe=pefile.PE(data=old);b=bytearray(old);allowed=[]
for name,value in [('MajorOperatingSystemVersion',6),('MinorOperatingSystemVersion',1),('MajorSubsystemVersion',6),('MinorSubsystemVersion',1)]:
 offset=pe.OPTIONAL_HEADER.get_field_absolute_offset(name);allowed.extend([offset,offset+1]);struct.pack_into('<H',b,offset,value)
changed=[i for i in range(len(old))if old[i]!=b[i]];assert changed and set(changed)<=set(allowed)
candidate=pefile.PE(data=b)
assert [(x.Name,x.get_data())for x in pe.sections]==[(x.Name,x.get_data())for x in candidate.sections]
path=P/'G67-client-header61.exe'
if path.exists():assert path.read_bytes()==b
else:path.write_bytes(b)
s.update(original_sha256=hashlib.sha256(old).hexdigest(),candidate_sha256=hashlib.sha256(b).hexdigest(),changed_file_offsets=changed,only_four_header_version_fields_changed=True,all_raw_sections_byte_identical=True,native_clock_trial_requested=False);R.persist()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
assert op('stage-header-only-candidate','put',file=path,path=path.name)['sha256']==s['candidate_sha256']
assert op('hash-header-only-candidate','hash',path='X:\\OpenG17\\payloads\\'+path.name)['sha256']==s['candidate_sha256']
if'nonce'not in s:s['nonce']=uuid.uuid4().hex;R.persist()
r=R.op('single-header-only-query','phone','exec',argv=['X:\\OpenG17\\payloads\\'+path.name,'query',s['nonce']]);s['execution']=r;R.persist();s['phase']='metadata_only_native_startup_comparison_retained';R.persist();print(json.dumps({'phase':s['phase'],'execution':r}))
