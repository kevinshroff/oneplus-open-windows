"""Generate fixed report-reader extent identities from the pinned G147 replay."""
from pathlib import Path
import argparse,hashlib,json,subprocess
w=Path(__file__).resolve().parent;p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--replay',type=Path,default=w.parent/'charging-G147/private/main-target-replay-04.json')
p.add_argument('--output',required=True,type=Path);a=p.parse_args();assert not a.output.exists()
raw=a.replay.read_bytes();assert hashlib.sha256(raw).hexdigest()=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(raw);assert j['passed']and j['cases']==8
plan=j['complete_target_plan'];assert len(plan)==89 and sum(r['bytes'] for r in plan)==64910785
assert sum(r['kind']=='file-copy-model'for r in plan)==54 and sum(r['kind']=='zero-model'for r in plan)==35
rows=[];end=0
for r in plan:
 assert 0x9ea00000<=r['address']<r['address']+r['bytes']<=0xa3280000 and r['address']>=end
 end=r['address']+r['bytes'];kind=1 if r['kind']=='file-copy-model'else 2
 digest=r['sha256']if kind==1 else'0'*64;assert len(bytes.fromhex(digest))==32
 rows.append('{%d,%s,%d,"%s"},'%(kind,hex(r['address']),r['bytes'],digest))
a.output.write_text('package main\n// Fixed G147 c92416ad... original-loader extent identities. No runtime selector.\ntype mainExtent struct {kind uint32;base,bytes uint64;digest string}\nvar mainPlan = [...]mainExtent{\n'+'\n'.join(rows)+'\n}\n')
subprocess.run(['gofmt','-w',str(a.output)],check=True)
print(json.dumps({'extents':89,'source_report_sha256':hashlib.sha256(raw).hexdigest(),'plan_sha256':hashlib.sha256(a.output.read_bytes()).hexdigest()}))
