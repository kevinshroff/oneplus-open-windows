"""Exact archived FAT ZIPs, old plans and redundant copies of one read-only probe."""
from pathlib import Path
import hashlib,json,re
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('reclaim-more-duplicates.json');s=R.s
assert json.loads((W/'reclaim-duplicates.json').read_text())['phase']=='two_archived_project_duplicates_reclaimed'
entries=[]
def add(remote,local):
    assert re.fullmatch(r'X:\\OpenG17\\payloads\\[A-Za-z0-9_.-]+',remote)
    assert local.is_file();entries.append({'path':remote,'local':str(local),'bytes':local.stat().st_size,'sha256':hashlib.sha256(local.read_bytes()).hexdigest()})
for area in ['gpio-G21','gpio-G22']:
    b=json.loads((W.parent/area/'fresh-FAT-backup.json').read_text());p=Path(b['file']).parent
    for i in [0,1]:
        t=b['manifest']['pieces'][i];local=p/('%02d.zip'%i)
        assert hashlib.sha256(local.read_bytes()).hexdigest()==t['zip_sha256']and local.stat().st_size==t['zip_bytes']
        add(t['path'],local)
for remote,local in [('G22-wim-forward.json','G22-wim-forward.json'),('G22-wim-inverse.json','G22-wim-inverse.json'),('G22-WIM-update.journal.json','native-WIM-update.journal.json')]:
    add('X:\\OpenG17\\payloads\\'+remote,W.parent/'gpio-G22/private'/local)
for gen in ['G20','G21','G22','G23','G25','G26','G28','G39']:
    add('X:\\OpenG17\\payloads\\'+gen+'-readonly-probe.exe',W.parent/'firmware-trial/readonly-probe-arm64.exe')
s['verified_Mac_copies']=entries;R.persist()
for i,e in enumerate(entries):
    r=R.op('native-hash-%02d'%i,'phone','hash',path=e['path']);assert r['status']=='ok'and r['sha256']==e['sha256'],e
s['all_native_hashes_match_retained_Mac_copies']=True;R.persist()
r=R.op('delete-exact-archived-duplicates','phone','exec',argv=['cmd.exe','/d','/c','del /q '+' '.join(e['path']for e in entries)])
assert r['status']=='ok'and r.get('exit_code',0)==0
r=R.op('verify-remaining-files-and-free-space','phone','exec',argv=['cmd.exe','/d','/c',r'dir /a:-d /-c X:\OpenG17\payloads']);assert r['status']=='ok'
for e in entries:assert Path(e['path'].replace('\\','/')).name.lower()not in r['output'].lower()
m=re.search(r'(\d+) bytes free',r['output']);assert m and int(m[1])>60*1024*1024
s.update(phase='archived_duplicates_reclaimed_and_absence_verified',raw_partition_writes=0,bytes_reclaimed=sum(e['bytes']for e in entries),free_bytes_after=int(m[1]));R.persist()
print(json.dumps({k:s[k]for k in ['phase','bytes_reclaimed','free_bytes_after']}),flush=True)
