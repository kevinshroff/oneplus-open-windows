"""Build the separately audited resource namespace image; no phone operations."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess
w=Path(__file__).resolve().parent;p=w/'private';f=p/'firmware-build.json';assert not f.exists(),'Observe the recorded build; no uncertain install replay'
v=json.loads((p/'firmware-source.json').read_text());sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();s=p/'firmware-source'
assert {str(f.relative_to(s)):sha(f)for f in s.rglob('*')if f.is_file()}==v['candidate']
state={'phase':'preparing','pid':os.getpid(),'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'native_phone_operations':0};save=lambda:f.write_text(json.dumps(state,indent=2)+'\n');save()
script='''from pathlib import Path
import hashlib,json,os
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');s=Path(%r);v=json.loads(%r);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
for n,h in v['prior'].items():assert sha(r/n)==h,('Existing qualified source mismatch',n)
assert sha(r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')=='20f49eaedb87dff05866bf501649e3ba97d126417eb4abd0107f3a1475cfbacb'
for n in v['added']:assert not(r/n).exists(),n
for n,h in v['candidate'].items():
 assert sha(s/n)==h,n
 if v['prior'].get(n)==h:continue
 tmp=(r/n).with_name((r/n).name+'.G182-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,r/n)
 assert sha(r/n)==h,n
print(json.dumps({'prior_files':len(v['prior']),'modified':len(v['changed']),'added':len(v['added'])}))
'''%(str(s),json.dumps(v))
r=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);(p/'firmware-install.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr[-3000:];state.update(phase='building',source_install=json.loads(r.stdout));save()
cmd='source ~/woa-open/venv/bin/activate && source ~/woa-open/build-env.sh && cd /home/PROJECT_USER.guest/woa-open/mu_aloha_platforms && python3 build_uefi.py -d oneplus-open -t DEBUG'
with(p/'firmware-build.log').open('wb')as out:r=subprocess.run(['colima','ssh','--','bash','-lc',cmd],stdout=out,stderr=subprocess.STDOUT)
log=(p/'firmware-build.log').read_text(errors='replace');assert not r.returncode and '121 Images Verified'in log and 'PROGRESS - Success'in log,log[-4000:]
script='''from pathlib import Path
import json,hashlib
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');p=Path(%r);v=json.loads(%r);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
for n,h in v['candidate'].items():assert sha(r/n)==h,n
files={}
for old,new in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G182-resources.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G182-resources.img'),('Build/KailuaPkg/DEBUG_CLANGPDB/AARCH64/MdeModulePkg/Universal/BdsDxe/BdsDxe/OUTPUT/BdsDxe.map','BdsDxe-linked.map')]:
 f=p/new
 with f.open('xb')as out:out.write((r/old).read_bytes())
 files[new]={'sha256':sha(f),'bytes':f.stat().st_size}
print(json.dumps(files))
'''%(str(p),json.dumps(v))
r=subprocess.run(['colima','ssh','--','python3','-c',script],capture_output=True,text=True);assert not r.returncode,r.stderr;state.update(phase='built_awaiting_audit',files=json.loads(r.stdout),finished=datetime.datetime.now(datetime.timezone.utc).isoformat());save();print(state)
