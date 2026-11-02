"""Build fixed ARM64 local collection; exact admitted child tools, no phone calls."""
from pathlib import Path
import base64,hashlib,json,os,shutil,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
ready=json.loads((p/'readiness.json').read_text());assert ready['compiled_sources_match']and ready['signed_CMS_verified_by_host']
pins={n:v['sha256']for n,v in ready['files'].items()}
for n,v in ready['files'].items():assert sha(Path(v['path']))==v['sha256'],n
prior=w.parent/'charging-G170';observer=json.loads((prior/'private/observer-build.json').read_text())
for n,h in observer['sources'].items():assert sha(prior/'helpers'/n)==h,n
assert sha(prior/'private/G170-observe.exe')==observer['sha256']
pins['G170-observe.exe']=observer['sha256'];pins.update(observer['pins']);assert len(pins)==10
for n in ['guard_windows.go','decode.go','abi.json']:shutil.copyfile(w/'client'/n,w/'helpers'/n)
subprocess.run(['gofmt','-w',str(w/'helpers/cycle_windows.go')],check=True)
encoded=base64.b64encode(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).decode()
flags='-buildid= -X main.cyclePins='+encoded
env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
files=['cycle_windows.go','guard_windows.go','decode.go']
subprocess.run(['go','build','-trimpath','-ldflags='+flags,'-o',str(p/'G177-cycle.exe'),*files],cwd=w/'helpers',env=env,check=True)
b=(p/'G177-cycle.exe').read_bytes();pe=struct.unpack_from('<I',b,60)[0];assert struct.unpack_from('<H',b,pe+4)[0]==0xaa64
v={'campaign':'G177','scope':'Fixed one-shot restart orchestration and four paired physical/config observations. Kernel timer owns normal off; failed/uncertain observers are retained. No raw command,property,value,duration API.','pins':pins,'sources':{f.name:sha(f)for f in(w/'helpers').iterdir()if f.is_file()},'build':{'files':files,'flags':flags},'sha256':sha(p/'G177-cycle.exe'),'bytes':len(b),'native_operations':0}
(p/'cycle-build.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in ['sha256','bytes','native_operations']})
