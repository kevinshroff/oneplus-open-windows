"""Pin full G180 native/recovery package without changing the phone."""
from pathlib import Path
import hashlib,json,py_compile
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();ready=json.loads((p/'readiness.json').read_text());assert ready['passed']and ready['signed_CMS_verified']
for n,h in ready['sources'].items():assert sha(w/n)==h,n
for n,h in ready['client_sources'].items():assert sha(w/'client'/n)==h,n
obs=json.loads((p/'host-observation.json').read_text());assert obs['pid']==1196 and obs['pipe']=='OpenG80'and not obs['task_has_trigger']
files={n:Path(v['path'])for n,v in ready['files'].items()};helper=json.loads((p/'helper-build.json').read_text())
for n,h in helper['sources'].items():assert sha(w/'helpers'/n)==h,n
assert sha(p/'G180-health.exe')==helper['sha256'];files['G180-health.exe']=p/'G180-health.exe'
for c in ['G167','G160']:
 root=w.parent/('charging-'+c);a=json.loads((root/'private/signature-and-source-audit.json').read_text());assert a['passed']and a['all_compiled_source_hashes_match']
 source=a.get('source_sha256',{})if c=='G167'else json.loads((root/'private/compile-02/compile.json').read_text())['sources']
 for n,h in source.items():assert sha(root/'probe'/n)==h,n
 for n,v in a['files'].items():assert sha(Path(v['path']))==v['sha256'];files[n]=Path(v['path'])
for n,h in {'G154-install-arm64.exe':'d6fb3079f3b02aef839724ec783be623af9b8c7c4ca9f8e174e599f2c631d5c7','G155-read-DSP.exe':'c85e5c2d32b0d4dcdaed3d6423eed1177ca67653223e9c3698e42d6ca98236aa'}.items():
 f=w.parent/('charging-G155/private/release/'+n if n.startswith('G154')else'charging-G155/private/'+n);assert sha(f)==h;files[n]=f
for n in ['Refresh-Debugger-G180.ps1','Boot-Existing-Image-G180.ps1','G180-Restore-EEM.ps1']:files[n]=w/n
old=json.loads((w.parent/'charging-G177/private/readiness.json').read_text())
for n,v in old['files'].items():assert sha(Path(v['path']))==v['sha256'];files[n]=Path(v['path'])
assert len(files)==18
for n,h in helper['pins'].items():assert sha(files[n])==h,n
scripts=['observe-host.py','stage-host.py','close-current.py','launch-fresh.py','native-stage-once.py','run-sustained-once.py','finish-build-once.py','build-clients.py','prepare-package.py']
for n in scripts:py_compile.compile(str(w/n),doraise=True)
m={'campaign':'G180','purpose':'Kernel health-gated FV/restart,90s renewable intervals/15min hard cap; read-only physical evidence and unchanged recovery boot.','previous_session':'00000000000000000000000000000000','host_session':'00000000000000000000000000000000','files':{n:{'path':str(f),'sha256':sha(f),'bytes':f.stat().st_size}for n,f in files.items()},'python_sha256':{n:sha(w/n)for n in scripts},'partition_flashes':0,'same_boot_PAS_retries':0,'G177_fallback_is_fresh_boot_only':True}
(p/'package.json').write_text(json.dumps(m,indent=2)+'\n');print({'package_files':len(files),'compiled_sources_match':True,'fixed_inputs':len(helper['pins']),'phone_operations':0})
