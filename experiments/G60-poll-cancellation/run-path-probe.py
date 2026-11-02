"""Native Windows-only path semantics, without any driver or MMIO calls."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('native-path-probe.json');p=W/'private/path-probe-01/g60-path-probe-arm64.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();remote=r'X:\OpenG17\payloads\G60-path-probe.exe'
r=R.op('put-probe','phone','put',file=p,path=remote);assert r['status']=='ok'and r['sha256']==sha(p);r=R.op('hash-probe','phone','hash',path=remote);assert r['status']=='ok'and r['sha256']==sha(p)
r=R.op('run-pure-path-probe','phone','exec',argv=[remote]);assert r['status']=='ok'and not r.get('exit_code',0),r;v=json.loads(r['output']);assert v['passed']and v['cases']==18 and v['MMIO_or_driver_requests']==0;R.s['result']=v;R.s.update(phase='actual_Windows_path_semantics_passed',predicate_source_sha256=sha(W/'g59_paths.go'),binary_sha256=sha(p));R.persist();print(json.dumps(v))
