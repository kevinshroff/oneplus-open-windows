"""Build a fixed read-only native observer batch; no phone operations."""
from pathlib import Path
import base64,hashlib,json,os,subprocess
w=Path(__file__).resolve().parent;sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();pins={}
for c in ['G167','G160']:
 audit=json.loads((w.parent/('charging-'+c)/'private/signature-and-source-audit.json').read_text());assert audit['passed']and audit['all_compiled_source_hashes_match']
 for n,v in audit['files'].items():
  f=Path(v['path']);assert sha(f)==v['sha256'];pins[n]=v['sha256']
assert len(pins)==6
(w/'helpers/guard_windows.go').write_bytes((w/'client/guard_windows.go').read_bytes())
subprocess.run(['gofmt','-w',str(w/'helpers/observe_windows.go'),str(w/'helpers/guard_windows.go')],check=True)
env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
subprocess.run(['go','build','-trimpath','-ldflags=-buildid= -X main.observerFiles='+base64.b64encode(json.dumps(pins,separators=(',',':')).encode()).decode(),'-o',str(w/'private/G170-observe.exe'),'observe_windows.go','guard_windows.go'],cwd=w/'helpers',env=env,check=True)
proof={'scope':'Batch exact previously audited G167/G160 observers; no GLINK request or PMIC configuration','pins':pins,'sources':{f.name:sha(f)for f in(w/'helpers').iterdir()if f.is_file()},'sha256':sha(w/'private/G170-observe.exe'),'native_operations':0}
(w/'private/observer-build.json').write_text(json.dumps(proof,indent=2)+'\n');print({'observer_sha256':proof['sha256'],'fixed_files':len(pins)})
