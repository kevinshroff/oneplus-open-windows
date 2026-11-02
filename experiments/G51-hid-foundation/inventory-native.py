from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('inventory-native.json');binary=W/'private/inventory-build-01/g51-inventory-arm64.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();meta=json.loads((binary.parent/'build.json').read_text());assert meta['source_sha256']==sha(W/'g51_manage.go')and meta['binary_sha256']==sha(binary)
remote=r'X:\OpenG17\payloads\G51-input-inventory.exe'
assert R.op('put','phone','put',file=binary,path=remote)['sha256']==sha(binary)
assert R.op('hash','phone','hash',path=remote)['sha256']==sha(binary)
r=R.op('inventory','phone','exec',argv=[remote,'inventory']);assert r['status']=='ok'and r.get('exit_code')==0,r
v=json.loads(r['output']);assert v['ok'];R.s['result']=v['result'];R.persist();print(json.dumps(v['result'],indent=2))
p=W/'private/input.inf';r=R.op('input-inf','phone','get',path=r'X:\Windows\INF\input.inf',save=p if not p.exists()else None);assert r['status']=='ok'and sha(p)==r['sha256']
