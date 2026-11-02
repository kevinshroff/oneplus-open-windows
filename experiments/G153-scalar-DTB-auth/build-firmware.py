"""Build the scalar-hash DTB-only correction from the exact current G151 guest.
No host/phone controller command is issued by this script.
"""
from pathlib import Path
import datetime,hashlib,json,os,subprocess
w=Path(__file__).resolve().parent;p=w/'private';source=p/'candidate-source'
lib=Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
load=lambda f:json.loads(f.read_text())
candidate=load(p/'candidate-source-hashes.json')
assert len(candidate)==31
for n,h in candidate.items():assert sha(source/n)==h,n
for folder,cases in [('admission-model-01',96),('adapter-model-02',72)]:
 d=load(p/folder/'tests.json');assert d['passed']and d['cases']==cases
 for n,h in d['source_sha256'].items():assert sha(w/n)==h,n
assert sha(w/'OpenSha256.h')=='33b1ac0bab27454237686000ee66f8c9604c68fbaa90bc06545ca089e2dac227'
old=load(w.parent/'charging-G146/private/candidate-source-hashes.json')
changed=[n for n in candidate if n not in old or candidate[n]!=old[n]]
assert {Path(n).name for n in changed}=={'OpenSha256.h','OpenDtbAdmission.c','DeviceBootManagerLib.inf','OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenAdspPreflight.c'}
# Prove the scope beyond campaign identities, SHA dependency and exact call.
for n,h in old.items():
 text=(source/n).read_text().replace('G153','G146').replace('OemRevision=153','OemRevision=146').replace('OemRevision = 153','OemRevision = 146')
 before=(w.parent/'charging-G146/private/candidate-source'/n).read_text()
 if Path(n).name not in ['OpenDtbAdmission.c','DeviceBootManagerLib.inf']:assert text==before,n
assert 'Sha256HashAll'not in (w/'OpenDtbAdmission.c').read_text()
assert 'BaseCryptLib'not in (w/'DeviceBootManagerLib.inf').read_text()
baseline=load(w.parent/'boot-repair-G80/private/firmware-normal/source-hashes.json')
for g in ['G119','G128','G131','G133','G134','G136','G139','G144','G146','G151']:
 baseline.update(load(w.parent/('charging-'+g)/'private/candidate-source-hashes.json'))
state=p/'build-state.json';assert not state.exists(),'Observe existing build; do not replay.'
status={'state':'preparing','pid':os.getpid(),'started_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'native_operations':0,'changed_from_G146':changed}
def save(**kw):status.update(kw);state.write_text(json.dumps(status,indent=2)+'\n')
save()
install='''from pathlib import Path
import hashlib,json,os,subprocess
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');s=Path(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip()=='68ae12fafdcd873240d8635afecac542c2c4c563'
baseline=json.loads(%r);candidate=json.loads(%r)
for n,h in baseline.items():assert(r/n).is_file()and not(r/n).is_symlink()and sha(r/n)==h,('baseline',n)
assert sha(r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')=='4ca01e01f23ee141321d77ecff51aecc4f829e5a77334714cd5d2b3a84219ed3'
for n,h in candidate.items():assert n in baseline and sha(s/n)==h,n
written=[]
for n,h in candidate.items():
 if sha(r/n)==h:continue
 tmp=(r/n).with_name((r/n).name+'.G153-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,r/n);assert sha(r/n)==h;written.append(n)
print(json.dumps({'baseline_files':len(baseline),'candidate_files':len(candidate),'files_written':written}))
'''%(str(source),json.dumps(baseline),json.dumps(candidate))
try:
 r=subprocess.run(['colima','ssh','--','python3','-c',install],capture_output=True,text=True)
 (p/'source-install.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
 save(state='building',source_install=json.loads(r.stdout))
 command='source ~/woa-open/venv/bin/activate && source ~/woa-open/build-env.sh && cd /home/PROJECT_USER.guest/woa-open/mu_aloha_platforms && python3 build_uefi.py -d oneplus-open -t DEBUG'
 with(p/'build.log').open('wb')as f:r=subprocess.run(['colima','ssh','--','bash','-lc',command],stdout=f,stderr=subprocess.STDOUT)
 log=(p/'build.log').read_text(errors='replace');assert r.returncode==0 and 'PROGRESS - Success'in log and '121 Images Verified'in log,log[-6000:]
 collect='''from pathlib import Path
import hashlib,json
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');out=Path(%r);candidate=json.loads(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,h in candidate.items():assert sha(r/n)==h,n
files={}
for a,b in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G153-dtb-auth.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G153-dtb-auth.img')]:
 p=out/b
 with p.open('xb')as f:f.write((r/a).read_bytes())
 files[b]={'bytes':p.stat().st_size,'sha256':sha(p)}
print(json.dumps({'files':files,'map_candidates':[str(x)for x in(r/'Build/KailuaPkg/DEBUG_CLANGPDB').rglob('DeviceBootManagerLib.map')]}))
'''%(str(p),json.dumps(candidate))
 r=subprocess.run(['colima','ssh','--','python3','-c',collect],capture_output=True,text=True);assert r.returncode==0,r.stderr
 save(state='built_awaiting_audit',**json.loads(r.stdout),finished_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat());print(json.dumps(status,indent=2))
except BaseException as e:save(state='failed',error=str(e)[-9000:]);raise
