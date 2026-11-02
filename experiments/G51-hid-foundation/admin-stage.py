from pathlib import Path
import json,hashlib
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('admin-stage.json');binary=W/'private/admin-build-03/g51-admin-arm64.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();m=json.loads((binary.parent/'build.json').read_text());assert m['source_sha256']==sha(W/'g51_admin.go')and m['binary_sha256']==sha(binary);assert json.loads((W/'private/ABI-model-02/tests.json').read_text())['source_sha256']==sha(W/'g51_admin.go')
remote=r'X:\OpenG17\payloads\G51-admin.exe';assert R.op('put','phone','put',file=binary,path=remote)['sha256']==sha(binary);assert R.op('hash','phone','hash',path=remote)['sha256']==sha(binary)
r=R.op('roots-before','phone','exec',argv=[remote,'roots']);assert r['status']=='ok'and r.get('exit_code')==0,r;v=json.loads(r['output']);assert v['ok']and not v['result']['owned_roots'],v;R.s['phase']='manager_staged_no_owned_root';R.persist();print(json.dumps(v))
