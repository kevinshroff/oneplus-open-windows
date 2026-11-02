"""Restore one absent inbox include from identity-matched Windows media."""
from pathlib import Path
import argparse, hashlib, json
from relay import Relay

p=argparse.ArgumentParser()
p.add_argument('--phase',required=True,choices=['stage','restore','undo'])
a=p.parse_args()
W=Path(__file__).resolve().parent
R=Relay('dependency-native.json')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=W/'private/dependency-build-01/g51-dependency-arm64.exe'
m=json.loads((b.parent/'build.json').read_text())
assert m['source_sha256']==sha(W/'g51_dependency.go') and m['binary_sha256']==sha(b)
remote=r'X:\OpenG17\payloads\G51-dependency.exe'
inf=W/'private/inbox-dependency-01/Windows/INF/mshidkmdf.inf'
staged=r'X:\OpenG17\payloads\G51-mshidkmdf.inf'
manifest=W/'private/package.json'
args=[r'X:\OpenG17\payloads\G51-package\package.json',sha(manifest)]
assert sha(inf)=='086cfd93451de78d172384de4956a04443eb5d92576db316471085066558f92a'

if a.phase=='stage':
    for label,local,dest in [('helper',b,remote),('inbox-include',inf,staged)]:
        assert R.op('put-'+label,'phone','put',file=local,path=dest)['sha256']==sha(local)
        assert R.op('hash-'+label,'phone','hash',path=dest)['sha256']==sha(local)
    R.s['phase']='guarded_helper_and_exact_inbox_dependency_staged'
else:
    if a.phase=='restore':
        assert R.s['phase']=='guarded_helper_and_exact_inbox_dependency_staged'
    argv=[remote,a.phase,*args]+([staged] if a.phase=='restore' else [])
    r=R.op(a.phase,'phone','exec',argv=argv)
    assert r['status']=='ok' and r.get('exit_code')==0,r
    v=json.loads(r['output']);assert v['ok'],v
    R.s[a.phase]=v['result']
    R.s['phase']='inbox_include_restored' if a.phase=='restore' else 'owned_inbox_include_removed'
R.persist()
print(json.dumps({k:v for k,v in R.s.items() if k!='jobs'},indent=2))
