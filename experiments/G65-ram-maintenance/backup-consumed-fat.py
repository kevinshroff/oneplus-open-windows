"""Retain the fresh post-maintenance FAT before preparing a distinct trial boot."""
from pathlib import Path
import hashlib,json,re,zipfile
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-ram.json').read_text());u=json.loads((W/'native-WIM-update.json').read_text())
assert u['phase']=='native_RAM_controlled_trial_WIM_update_and_full_readback_verified'
assert b['root']['x_is_ramdisk'] and b['all_six_GPTs_byte_identical_to_baseline']
R=Relay('fresh-trial-FAT-backup.json',phone_session=b['session']);s=R.s
sha=lambda b:hashlib.sha256(b).hexdigest()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok' and r.get('exit_code',0)==0,r;return r
tool=r'X:\OpenG17\payloads\G65-disktool-r6.exe'
q=json.loads((W/'updater-native-qualification.json').read_text())
assert op('updater-hash','hash',path=tool)['sha256']==q['binary_sha256']
prefix=r'X:\OpenG17\payloads\G65-FAT-trial-preimage'
r=op('single-fresh-FAT-capture','exec',argv=[tool,'backup','userdata','0','268435456',prefix],timeout=180)
m=json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
assert m['raw_writes']==0 and m['access']=='GENERIC_READ'
assert m['raw_sha256']==q['FAT_before']['sha256']
s['native_manifest']=m;R.persist()
raw=bytearray()
for i,piece in enumerate(m['pieces']):
 assert re.fullmatch(re.escape(prefix)+r'-\d{3}\.zip',piece['path'])
 p=P/('trial-FAT-piece-%02d.zip'%i)
 op('retain-piece-%02d'%i,'get',path=piece['path'],save=p)
 assert sha(p.read_bytes())==piece['zip_sha256']
 with zipfile.ZipFile(p)as z:
  assert z.testzip() is None and z.namelist()==['raw.bin'];data=z.read('raw.bin')
 assert len(data)==piece['raw_bytes'] and sha(data)==piece['raw_sha256'] and len(raw)==piece['offset']
 raw.extend(data)
assert len(raw)==268435456 and sha(raw)==m['raw_sha256']
p=P/'userdata-after-maintenance.img'
if p.exists():assert p.read_bytes()==raw
else:
 with p.open('xb')as f:f.write(raw)
s.update(phase='fresh_post_maintenance_FAT_retained_and_verified',file=str(p),sha256=sha(raw),
         bytes=len(raw),raw_writes=0,session=b['session'])
R.persist();print(json.dumps({k:s[k]for k in ['phase','sha256','bytes','raw_writes']}),flush=True)
