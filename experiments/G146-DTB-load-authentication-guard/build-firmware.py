"""Build the separately admitted DTB-copy/auth candidate; never operate the phone."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess

w=Path(__file__).resolve().parent;p=w/'private';source=p/'candidate-source'
lib=Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda path:json.loads(path.read_text())
g144=w.parent/'charging-G144/private';g139=w.parent/'charging-G139/private';g136=w.parent/'charging-G136/private'
old=load(g144/'candidate-source-hashes.json')
candidate={str(f.relative_to(source)):sha(f.read_bytes()) for f in sorted(source.rglob('*')) if f.is_file()}
added=set(candidate)-set(old)
assert len(candidate)==30 and not(set(old)-set(candidate))
assert {Path(n).name for n in added}=={'OpenDtbAdmission.c','OpenDtbAdmission.h'}
changed=[n for n in candidate if n not in old or candidate[n]!=old[n]]
assert {Path(n).name for n in changed}=={'OpenDtbAdmission.c','OpenDtbAdmission.h','DeviceBootManagerLib.inf','OpenAdspPreflight.c','OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenPasObserver.h','OpenScmErrorCapture.c'}
for n in changed:assert (w/Path(n).name).read_bytes()==(source/n).read_bytes(),n

def gate(path,cases,names,field='source_sha256'):
 d=load(path);assert d['passed'] and d['cases']==cases,path
 for n in names:assert sha((source/lib/n).read_bytes())==d[field][n],(path,n)
 return d

gate(p/'admission-model-01/tests.json',97,['OpenDtbAdmission.c','OpenDtbAdmission.h'])
gate(p/'adapter-model-01/tests.json',72,['OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenPasObserver.h','OpenScmErrorCapture.c','OpenScmErrorCapture.h'])
gate(p/'observer-model-01/tests.json',41,['OpenPasObserver.c','OpenPasObserver.h'])
gate(p/'error-capture-model-01/tests.json',130,['OpenScmErrorCapture.c','OpenScmErrorCapture.h'])
# Reuse only byte-identical inherited components.
gate(g144/'footprint-model-01/tests.json',96,['OpenPilFootprint.c','OpenPilFootprint.h'])
gate(g144/'cpu-admission-model-01/tests.json',29,['OpenDspAdmission.c','OpenDspAdmission.h'])
g134=w.parent/'charging-G134/private'
gate(g134/'footprint-model-01/tests.json',68,['OpenKernelFootprint.c','OpenKernelFootprint.h'])
gate(g134/'metadata-probe-model-01/tests.json',31,['OpenPilMetadataProbe.c','OpenPilMetadataProbe.h'])
gate(g139/'cpu-model-01/tests.json',15,['OpenPilCpuInventory.c','OpenPilCpuInventory.h'])
gate(g139/'publisher-model-03/tests.json',14,['OpenPilInventory.c','OpenPilCpuInventory.c','OpenPilCpuInventory.h'])
facade=load(p/'preflight-test-results.json');assert facade['passed']and facade['cases']==34
assert facade['source_sha256']==sha((source/lib/'OpenAdspPreflight.c').read_bytes())
reader=load(p/'reader-verification.json');assert reader['passed']and reader['leaf_cases']==138
for name,digest in reader['source_sha256'].items():assert sha((w/'report-reader'/name).read_bytes())==digest
assert sha((p/'G146-read-DSP.exe').read_bytes())==reader['exe_sha256']
replay=load(p/'DTB-target-replay-03.json');assert replay['passed']and replay['cases']==7
baseline=load(w.parent/'boot-repair-G80/private/firmware-normal/source-hashes.json')
for campaign in ['G119','G128','G131','G133','G134','G136','G139','G144']:
 baseline.update(load(w.parent/('charging-'+campaign)/'private/candidate-source-hashes.json'))
assert baseline[str(lib/'ReadOnlyBlockIo.c')]==facade['native_ReadOnlyBlockIo_sha256']
(p/'candidate-source-hashes.json').write_text(json.dumps(candidate,indent=2)+'\n')
state=p/'build-state.json';assert not state.exists(),'Observe the prior build; never replay an uncertain install.'
status={'state':'preparing','pid':os.getpid(),'started_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'native_phone_operations':0,'changed_sources':changed,
 'scope':'One DTB36 INIT/MEM_SETUP, original 8376-byte copy at9E980000, fresh finite reservation/CPU/display/hash admission, DTB AUTH then original POST. Main is blocked; no remapping, partition flash, shutdown or same-boot retry.'}
def save(**kw):
 status.update(kw);state.write_text(json.dumps(status,indent=2)+'\n')
save()
install='''from pathlib import Path
import hashlib,json,os,subprocess
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');s=Path(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip()=='68ae12fafdcd873240d8635afecac542c2c4c563'
expected=json.loads(%r);candidate=json.loads(%r)
for n,h in expected.items():assert (r/n).is_file() and not(r/n).is_symlink() and sha(r/n)==h,('Baseline',n)
assert sha(r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')=='ecf2d06d439a5d93f18e0ac2e0fd4746016e6eddeb3aff02d20a533461b83498'
for n,h in candidate.items():assert sha(s/n)==h and (n in expected or n.endswith(("/OpenDtbAdmission.c","/OpenDtbAdmission.h"))),n
for n in candidate:
 if n not in expected:assert not(r/n).exists(),("New file unexpectedly exists",n)
written=0
for n,h in candidate.items():
 if (r/n).is_file() and sha(r/n)==h:continue
 tmp=(r/n).with_name((r/n).name+'.G146-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,r/n);assert sha(r/n)==h;written+=1
assert written==9
print(json.dumps({'baseline_files':len(expected),'candidate_files':len(candidate),'files_written':written,'native_phone_operations':0}))
'''%(str(source),json.dumps(baseline),json.dumps(candidate))
try:
 r=subprocess.run(['colima','ssh','--','python3','-c',install],capture_output=True,text=True)
 (p/'source-install.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr[-5000:]
 save(state='building',source_install=json.loads(r.stdout))
 command=('source ~/woa-open/venv/bin/activate && source ~/woa-open/build-env.sh && '
          'cd /home/PROJECT_USER.guest/woa-open/mu_aloha_platforms && python3 build_uefi.py -d oneplus-open -t DEBUG')
 with(p/'build.log').open('wb')as stream:r=subprocess.run(['colima','ssh','--','bash','-lc',command],stdout=stream,stderr=subprocess.STDOUT)
 log=(p/'build.log').read_text(errors='replace')
 assert r.returncode==0 and 'PROGRESS - Success' in log and '121 Images Verified' in log,log[-6000:]
 collect='''from pathlib import Path
import hashlib,json
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');out=Path(%r);candidate=json.loads(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,h in candidate.items():assert sha(r/n)==h,n
files={}
for old,new in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G146-dtb-auth.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G146-dtb-auth.img')]:
 p=out/new
 with p.open('xb')as f:f.write((r/old).read_bytes())
 files[new]={'bytes':p.stat().st_size,'sha256':sha(p)}
maps=list((r/'Build/KailuaPkg/DEBUG_CLANGPDB').rglob('DeviceBootManagerLib.map'))
print(json.dumps({'files':files,'map_candidates':[str(x) for x in maps]}))
'''%(str(p),json.dumps(candidate))
 r=subprocess.run(['colima','ssh','--','python3','-c',collect],capture_output=True,text=True);assert r.returncode==0,r.stderr
 save(state='built_awaiting_audit',**json.loads(r.stdout),finished_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat())
 print(json.dumps(status,indent=2))
except BaseException as error:
 save(state='failed',error=str(error)[-9000:]);raise
