"""Pin unchanged native tools and new one-shot G181 recovery/test controllers."""
from pathlib import Path
import hashlib,json,py_compile
w=Path(__file__).resolve().parent;p=w/'private';old=w.parent/'charging-G180';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
obs=json.loads((p/'host-observation.json').read_text());assert obs['pid']==10168 and not obs['task_has_trigger']
m=json.loads((old/'private/package.json').read_text());files={n:Path(v['path'])for n,v in m['files'].items()if not n.endswith('.ps1')}
for n,v in m['files'].items():
 if not n.endswith('.ps1'):assert sha(Path(v['path']))==v['sha256'],n
for n in ['Refresh-Debugger-G181.ps1','Boot-Existing-Image-G181.ps1','G181-Restore-EEM.ps1']:files[n]=w/n
observer=w.parent/'charging-G170';v=json.loads((observer/'private/observer-build.json').read_text())
for n,h in v['sources'].items():assert sha(observer/'helpers'/n)==h,n
f=observer/'private/G170-observe.exe';assert sha(f)==v['sha256'];files[f.name]=f
for n,h in v['pins'].items():assert sha(files[n])==h,n
assert len(files)==19
scripts=['observe-host.py','stage-host.py','close-current.py','launch-fresh.py','native-stage-once.py','run-expiry-once.py','postboot-host.py','prepare-package.py']
for n in scripts:py_compile.compile(str(w/n),doraise=True)
ready=json.loads((old/'private/readiness.json').read_text());assert ready['passed']and ready['signed_CMS_verified']
for n,h in ready['sources'].items():assert sha(old/n)==h,n
r={'campaign':'G181','purpose':'Exact G180 driver90s default charging expiry with zero renewals; independent physical on/off and one late refusal. No new driver or generic API.','previous_session':'00000000000000000000000000000000','host_session':'00000000000000000000000000000000','files':{n:{'path':str(f),'sha256':sha(f),'bytes':f.stat().st_size}for n,f in files.items()},'python_sha256':{n:sha(w/n)for n in scripts},'partition_flashes':0,'same_boot_PAS_retries':0,'source_driver_campaign':'G180'}
(p/'package.json').write_text(json.dumps(r,indent=2)+'\n');print({'files':len(files),'signed_driver_unchanged':True,'phone_operations':0})
