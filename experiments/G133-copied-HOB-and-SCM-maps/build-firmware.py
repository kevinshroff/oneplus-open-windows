"""Build the bounded HOB/SCM inventory from the pinned G131 VM baseline."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess
w=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
lib=Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
source=w/'private/candidate-source'
footprint=json.loads((w/'private/footprint-model-02/tests.json').read_text())
assert footprint['passed']and footprint['cases']==60
for n in ['OpenKernelFootprint.c','OpenKernelFootprint.h']:
 assert footprint['source_sha256'][n]==sha((w/n).read_bytes())==sha((source/lib/n).read_bytes())
lifecycle=json.loads((w.parent/'charging-G131/private/preflight-test-results.json').read_text())
assert lifecycle['passed']and lifecycle['source_sha256']==sha((source/lib/'OpenAdspPreflight.c').read_bytes())
metadata=json.loads((w.parent/'charging-G128/private/native-probe-model-03/tests.json').read_text())
assert metadata['passed']
for n in ['OpenPilMetadataProbe.c','OpenPilMetadataProbe.h']:
 assert metadata['source_sha256'][n]==sha((source/lib/n).read_bytes())
reader=(w/'private/report-reader-tests.txt').read_text();assert '\nPASS\n'in reader and '\nFAIL'not in reader
baseline=json.loads((w.parent/'boot-repair-G80/private/firmware-normal/source-hashes.json').read_text())
for campaign in ['G119','G128','G131']:
 baseline.update(json.loads((w.parent/('charging-'+campaign)/'private/candidate-source-hashes.json').read_text()))
candidate={str(p.relative_to(source)):sha(p.read_bytes())for p in sorted(source.rglob('*'))if p.is_file()};assert len(candidate)==14
(w/'private/candidate-source-hashes.json').write_text(json.dumps(candidate,indent=2)+'\n')
state=w/'private/build-state.json';assert not state.exists(),'Observe the existing build invocation'
status={'state':'preparing','pid':os.getpid(),'started_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'native_phone_operations':0,'changed_sources':sum(candidate[n]!=baseline.get(n)for n in candidate),'reused_checks':'Unchanged G131 preflight lifecycle and G128 metadata implementation; verified by hashes, not relabeled as new tests.'}
def save(**kw):status.update(kw);state.write_text(json.dumps(status,indent=2)+'\n')
save()
code='''from pathlib import Path
import hashlib,json,os,subprocess
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');s=Path(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip()=='68ae12fafdcd873240d8635afecac542c2c4c563'
expected=json.loads(%r);candidate=json.loads(%r)
for n,h in expected.items():assert (r/n).is_file()and not(r/n).is_symlink()and sha(r/n)==h,('Baseline',n)
assert sha(r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')=='5745e3898cc7cd6f6c306450c28893c933584a30c076d4582dff921d8e866106'
for n,h in candidate.items():
 assert n in expected and sha(s/n)==h
 p=r/n;tmp=p.with_name(p.name+'.G133-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,p);assert sha(p)==h
print(json.dumps({'baseline_files':len(expected),'candidate_files':len(candidate),'native_phone_operations':0}))
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
for old,new in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G133-metadata.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G133-metadata.img')]:
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
