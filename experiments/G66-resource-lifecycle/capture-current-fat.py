"""Reconstruct a fresh exact FAT using bounded native reads and a retained base."""
from pathlib import Path
import hashlib,json,zipfile
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private';B=W.parent/'ram-maintenance-G65'
base=json.loads((B/'fresh-trial-FAT-backup.json').read_text());src=Path(base['file'])
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=bytearray(src.read_bytes());assert len(raw)==268435456 and sha(raw)==base['sha256']
R=Relay('fresh-FAT.json');s=R.s
tool=r'X:\OpenG17\payloads\G18-disktool-r4.exe'
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def native(label,args):
 r=op(label,'exec',argv=[tool,*args],timeout=180)
 return json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
assert op('qualified-reader-hash','hash',path=tool)['sha256']=='7b944d4bf025423ab213b4ad133f8f9b59acd1e787b1875b551bc9735dfc902f'
start=native('fresh-whole-FAT-start',['hash','userdata','0','268435456']);assert start['raw_writes']==0
plan=json.loads((B/'private/G65v3-FAT-onetime.json').read_text())
offsets=sorted(c['offset']for c in plan['changes']);runs=[]
for o in offsets:
 assert o%4096==0 and o+4096<=len(raw)
 if runs and runs[-1][0]+runs[-1][1]==o and runs[-1][1]+4096<=65536:runs[-1][1]+=4096
 else:runs.append([o,4096])
s.update(source_file=str(src),source_sha256=base['sha256'],expected_whole_sha256=start['sha256'],read_ranges=runs);R.persist()
for i,(off,n)in enumerate(runs):
 prefix=r'X:\OpenG17\payloads\G66-FAT-read-'+str(i)
 m=native('read-range-'+str(i),['backup','userdata',str(off),str(n),prefix])
 assert m['raw_writes']==0 and m['access']=='GENERIC_READ'and m['offset']==off and m['bytes']==n and len(m['pieces'])==1
 piece=m['pieces'][0];assert piece['offset']==off and piece['raw_bytes']==n and piece['zip_bytes']<131072
 local=P/('FAT-range-'+str(i)+'.zip');op('retain-range-'+str(i),'get',path=piece['path'],save=local)
 assert sha(local.read_bytes())==piece['zip_sha256']
 with zipfile.ZipFile(local)as z:
  assert z.testzip()is None and z.namelist()==['raw.bin'];data=z.read('raw.bin')
 assert len(data)==n and sha(data)==m['raw_sha256']==piece['raw_sha256']
 raw[off:off+n]=data
s['reconstructed_sha256']=sha(raw);R.persist()
assert sha(raw)==start['sha256'],'Additional changed ranges require read-only hash bisection; do not weaken the full hash'
end=native('fresh-whole-FAT-end',['hash','userdata','0','268435456'])
assert end['sha256']==start['sha256']==sha(raw)and end['raw_writes']==0
dest=P/'userdata-before.img'
if dest.exists():assert sha(dest.read_bytes())==sha(raw)
else:
 with dest.open('xb')as f:f.write(raw)
s.update(phase='fresh_complete_FAT_reconstructed_from_actual_small_reads_and_verified_whole_hash',file=str(dest),sha256=sha(raw),bytes=len(raw),native_raw_bytes_captured=sum(n for _,n in runs),raw_writes=0,unread_bytes_proved_by_matching_whole_SHA256=True)
R.persist();print(json.dumps({k:s[k]for k in ['phase','sha256','bytes','native_raw_bytes_captured','raw_writes']}),flush=True)
