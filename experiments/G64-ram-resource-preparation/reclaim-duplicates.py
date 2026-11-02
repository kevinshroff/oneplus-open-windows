"""Reclaim only two exact archived project ZIPs; preserve every distinct byte."""
from pathlib import Path
import hashlib,json,re
from relay import Relay
W=Path(__file__).resolve().parent
sid='e79b94ed8322b13d61fa6152547629b3'
proof=json.loads((W/'storage-new-session-observation.json').read_text())
assert proof['sessions']['phone']==sid
root=json.loads(proof['jobs']['physical-root-read-only']['receipt']['output'])
env=json.loads(proof['jobs']['original-table-read-only']['receipt']['output'])['result']['environment']
assert not root['x_is_ramdisk']and env['DSDT_sha256']=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
old=json.loads((W.parent/'gpio-G23/fresh-FAT-backup.json').read_text());parent=Path(old['file']).parent
R=Relay('reclaim-duplicates.json',phone_session=sid);s=R.s;entries=[]
for i in [0,1]:
    t=old['manifest']['pieces'][i];p=parent/('%02d.zip'%i);h=hashlib.sha256(p.read_bytes()).hexdigest()
    assert p.stat().st_size==t['zip_bytes']and h==t['zip_sha256']
    assert re.fullmatch(r'X:\\OpenG17\\payloads\\G23-FAT-20261021T073743Z-00[01]\.zip',t['path'])
    r=R.op('native-hash-%d'%i,'phone','hash',path=t['path']);assert r['status']=='ok'and r['sha256']==h
    entries.append({'path':t['path'],'bytes':p.stat().st_size,'sha256':h,'retained_Mac_copy':str(p)})
s['verified_duplicates']=entries;s['raw_partition_writes']=0;R.persist()
r=R.op('delete-two-verified-duplicates','phone','exec',argv=['cmd.exe','/d','/c','del /q '+' '.join(e['path']for e in entries)])
assert r['status']=='ok'and r.get('exit_code',0)==0
for i,e in enumerate(entries):
    r=R.op('absence-%d'%i,'phone','hash',path=e['path']);assert r['status']=='error'and'cannot find'in r.get('error','').lower()
r=R.op('limited-free-space','phone','exec',argv=['cmd.exe','/d','/c',r'dir /a:-d /-c X:\OpenG17\payloads\G64-*.zip']);assert r['status']=='ok'
m=re.search(r'(\d+) bytes free',r['output']);assert m
s.update(phase='two_archived_project_duplicates_reclaimed',bytes_reclaimed=sum(e['bytes']for e in entries),free_bytes_after=int(m[1]));R.persist()
print(json.dumps({k:s[k]for k in ['phase','bytes_reclaimed','free_bytes_after']}),flush=True)
