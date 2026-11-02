"""Build the guarded one-use loader from the pinned native G133 baseline."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess
w=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
lib=Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
source=w/'private/candidate-source'
footprint=json.loads((w/'private/footprint-model-01/tests.json').read_text());assert footprint['passed']and footprint['cases']==68
for n in ['OpenKernelFootprint.c','OpenKernelFootprint.h']:assert footprint['source_sha256'][n]==sha((source/lib/n).read_bytes())
adapter=json.loads((w/'private/adapter-model-03/tests.json').read_text());assert adapter['passed']and adapter['cases']==47
for n in ['OpenGuardedAdsp.c','OpenGuardedAdsp.h','OpenPasObserver.c','OpenDspAdmission.c']:assert adapter['source_SHA256'][n]==sha((source/lib/n).read_bytes())
metadata=json.loads((w/'private/metadata-probe-model-01/tests.json').read_text());assert metadata['passed']and metadata['cases']==31
for n in ['OpenPilMetadataProbe.c','OpenPilMetadataProbe.h']:assert metadata['source_sha256'][n]==sha((source/lib/n).read_bytes())
observer=json.loads((w/'private/observer-model-02/tests.json').read_text());assert observer['passed']and observer['cases']==55
for n in ['OpenPasObserver.c','OpenPasObserver.h']:assert observer['sources'][n]==sha((source/lib/n).read_bytes())
cpu=json.loads((w/'private/admission-model-01.json').read_text());assert cpu['passed']and cpu['cases']==18
for n in ['OpenDspAdmission.c','OpenDspAdmission.h','OpenDspAt.c']:assert cpu['source_SHA256'][n]==sha((source/lib/n).read_bytes())
for n,cases in [('public-config-original-01.json',14),('relocated-original-range-01.json',2)]:
 r=json.loads((w/'private'/n).read_text());assert r['passed']and r['cases']==cases and r['native_operations']==0
# Facade lifecycle model may finish during this independent build. It and all
# wire readers remain mandatory release/staging gates; compilation grants no
# device-operation readiness.
lifecycle_path=w/'private/preflight-test-results.json'
if lifecycle_path.exists():
 lifecycle=json.loads(lifecycle_path.read_text());assert lifecycle['passed']and lifecycle['cases']==33 and lifecycle['source_sha256']==sha((source/lib/'OpenAdspPreflight.c').read_bytes())
baseline=json.loads((w.parent/'boot-repair-G80/private/firmware-normal/source-hashes.json').read_text())
for campaign in ['G119','G128','G131','G133']:
 baseline.update(json.loads((w.parent/('charging-'+campaign)/'private/candidate-source-hashes.json').read_text()))
candidate={str(p.relative_to(source)):sha(p.read_bytes())for p in sorted(source.rglob('*'))if p.is_file()};assert len(candidate)==21
(w/'private/candidate-source-hashes.json').write_text(json.dumps(candidate,indent=2)+'\n')
state=w/'private/build-state.json';assert not state.exists(),'Observe the existing build invocation'
status={'state':'preparing','pid':os.getpid(),'started_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'native_phone_operations':0,'changed_sources':sum(candidate[n]!=baseline.get(n)for n in candidate),'lifecycle_release_gate':'33-case integrated facade lifecycle required before release; build may run while its fixed source model completes.'}
def save(**kw):status.update(kw);state.write_text(json.dumps(status,indent=2)+'\n')
save()
code='''from pathlib import Path
import hashlib,json,os,subprocess
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');s=Path(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip()=='68ae12fafdcd873240d8635afecac542c2c4c563'
expected=json.loads(%r);candidate=json.loads(%r)
for n,h in expected.items():assert (r/n).is_file()and not(r/n).is_symlink()and sha(r/n)==h,('Baseline',n)
assert sha(r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')=='4eb6e25aba8f39bad406eb0223e0f505dd5af81017688a75d06fc8d42a45e0ed'
written=0
for n,h in candidate.items():
 assert sha(s/n)==h
 p=r/n
 if n not in expected:assert not p.exists(),('Unexpected pre-existing new source',n)
 if p.exists()and sha(p)==h:continue
 written+=1
 tmp=p.with_name(p.name+'.G134-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,p);assert sha(p)==h
print(json.dumps({'baseline_files':len(expected),'candidate_files':len(candidate),'files_written':written,'native_phone_operations':0}))
'''%(str(source),json.dumps(baseline),json.dumps(candidate))
try:
 r=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True);(w/'private/source-install.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr[-5000:]
 save(state='building',source_install=json.loads(r.stdout))
 command='source ~/woa-open/venv/bin/activate && source ~/woa-open/build-env.sh && cd /home/PROJECT_USER.guest/woa-open/mu_aloha_platforms && python3 build_uefi.py -d oneplus-open -t DEBUG'
 with(w/'private/build.log').open('wb')as f:r=subprocess.run(['colima','ssh','--','bash','-lc',command],stdout=f,stderr=subprocess.STDOUT)
 log=(w/'private/build.log').read_text(errors='replace');assert r.returncode==0 and 'PROGRESS - Success'in log and 'Images Verified'in log,log[-5000:]
 code='''from pathlib import Path
import hashlib,json
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');out=Path(%r);candidate=json.loads(%r);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,h in candidate.items():assert sha(r/n)==h,n
files={}
for old,new in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G134-guarded.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G134-guarded.img')]:
 p=out/new
 with p.open('xb')as f:f.write((r/old).read_bytes())
 files[new]={'bytes':p.stat().st_size,'sha256':sha(p)}
print(json.dumps(files))
'''%(str(w/'private'),json.dumps(candidate))
 r=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True);assert r.returncode==0,r.stderr
 save(state='built_awaiting_audit',files=json.loads(r.stdout),finished_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat())
 print(json.dumps(status,indent=2))
except BaseException as e:
 save(state='failed',error=str(e)[-9000:]);raise
