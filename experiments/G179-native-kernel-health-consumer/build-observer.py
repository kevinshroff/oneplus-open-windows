"""Build fixed local normal-path qualification, no phone operations."""
from pathlib import Path
import base64,hashlib,json,os,shutil,subprocess
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();r=json.loads((p/'readiness.json').read_text());assert r['passed'];pins={n:v['sha256']for n,v in r['files'].items()}
for n,h in r['sources'].items():assert sha(w/'source'/n)==h,n
for c in ['G167','G160']:
 root=w.parent/('charging-'+c);a=json.loads((root/'private/signature-and-source-audit.json').read_text());assert a['passed']and a['all_compiled_source_hashes_match']
 for n,h in a.get('source_sha256',{}).items():assert sha(root/'probe'/n)==h,n
 if c=='G160':
  m=json.loads((root/'private/compile-02/compile.json').read_text());assert m['passed']
  for n,h in m['sources'].items():assert sha(root/'probe'/n)==h,n
 for n,v in a['files'].items():assert sha(Path(v['path']))==v['sha256'];pins[n]=v['sha256']
reader=w.parent/'charging-G155/private/G155-read-DSP.exe';assert sha(reader)=='c85e5c2d32b0d4dcdaed3d6423eed1177ca67653223e9c3698e42d6ca98236aa';pins[reader.name]=sha(reader);assert len(pins)==10
shutil.copyfile(w/'client/guard_windows.go',w/'helpers/guard_windows.go');subprocess.run(['gofmt','-w',str(w/'helpers/observe_windows.go')],check=True)
flags='-buildid= -X main.observerFiles='+base64.b64encode(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).decode();env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0');subprocess.run(['go','build','-trimpath','-ldflags='+flags,'-o',str(p/'G179-observe.exe'),'observe_windows.go','guard_windows.go'],cwd=w/'helpers',env=env,check=True)
v={'sha256':sha(p/'G179-observe.exe'),'pins':pins,'sources':{f.name:sha(f)for f in(w/'helpers').iterdir()if f.is_file()},'build_flags':flags,'native_operations':0};(p/'observer-build.json').write_text(json.dumps(v,indent=2)+'\n');print({'observer_sha256':v['sha256'],'fixed_input_files':10})
