"""Install pinned source changes in the existing build VM and build, never deploy."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess,sys

w=Path(__file__).resolve().parent
source=w/'private/candidate-source'
lib=Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
test=json.loads((w/'private/preflight-test-results.json').read_text())
sha=lambda b:hashlib.sha256(b).hexdigest()
assert test['passed'] and test['cases']>=30
assert test['source_sha256']==sha((source/lib/'OpenAdspPreflight.c').read_bytes())
probe=json.loads((w.parent/'charging-G128/private/native-probe-model-03/tests.json').read_text());assert probe['passed'] and probe['cases']==31
assert probe['source_sha256']['OpenPilMetadataProbe.c']==sha((source/lib/'OpenPilMetadataProbe.c').read_bytes())
baseline=json.loads((w.parent/'boot-repair-G80/private/firmware-normal/source-hashes.json').read_text())
baseline.update({
 'Platforms/KailuaPkg/Device/oneplus-open/Binaries/RawFiles/uefiplat.cfg':'b142d920fca30826392838ecc1eba7bbbee4c8250854efd914527ee1afe32d3d',
 'Platforms/KailuaPkg/Device/oneplus-open/Binaries/RawFiles/uefipil.cfg':'13f509813bcaa5f862d0cdaa55e784c557bd0d9c9a93255185f2786a94b4c387',
})
baseline.update(json.loads((w.parent/'charging-G119/private/candidate-source-hashes.json').read_text()))
baseline.update(json.loads((w.parent/'charging-G128/private/candidate-source-hashes.json').read_text()))
footprint=json.loads((w/'private/footprint-model-02/tests.json').read_text());assert footprint['passed'] and footprint['cases']==41
for name in ['OpenKernelFootprint.c','OpenKernelFootprint.h']:
    assert footprint['source_sha256'][name]==sha((source/lib/name).read_bytes())
candidate={str(p.relative_to(source)):sha(p.read_bytes())for p in sorted(source.rglob('*'))if p.is_file()}
assert len(candidate)==14
(w/'private/candidate-source-hashes.json').write_text(json.dumps(candidate,indent=2)+'\n')
state=w/'private/build-state.json'
assert not state.exists(), 'Inspect the existing build invocation instead of rerunning it.'
def save(**kw):
    global status
    status.update(kw)
    state.write_text(json.dumps(status,indent=2)+'\n')
status={'state':'preparing','pid':os.getpid(),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'native_phone_operations':0,'source_files':len(candidate)}
save()
code='''from pathlib import Path
import hashlib,json,os
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
s=Path(%r)
expected=json.loads(%r)
candidate=json.loads(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,h in expected.items():
 p=r/n
 assert p.is_file() and not p.is_symlink() and sha(p)==h,('Baseline mismatch',n)
for n,h in candidate.items():
 assert n.startswith('Platforms/') and '..' not in Path(n).parts
 p=r/n
 if n not in expected:assert not p.exists(),('New source path already exists',n)
 assert (s/n).is_file() and sha(s/n)==h
fd=r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd'
assert sha(fd)=='fc9356a77480491d34496509ef1b8dd8c5f37d012f86e704a42767149aa2319c'
for n,h in candidate.items():
 p=r/n
 tmp=p.with_name(p.name+'.G131-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,p)
 assert sha(p)==h
print(json.dumps({'baseline_files_verified':len(expected),'candidate_files_installed':len(candidate),'native_phone_operations':0}))
'''%(str(source),json.dumps(baseline),json.dumps(candidate))
try:
    r=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True)
    (w/'private/source-install.log').write_text(r.stdout+r.stderr)
    assert r.returncode==0,r.stderr[-5000:]
    save(state='building',source_install=json.loads(r.stdout))
    command='source ~/woa-open/venv/bin/activate && source ~/woa-open/build-env.sh && cd /home/PROJECT_USER.guest/woa-open/mu_aloha_platforms && python3 build_uefi.py -d oneplus-open -t DEBUG'
    with (w/'private/build.log').open('wb')as f:
        r=subprocess.run(['colima','ssh','--','bash','-lc',command],stdout=f,stderr=subprocess.STDOUT)
    log=(w/'private/build.log').read_text(errors='replace')
    assert r.returncode==0 and 'PROGRESS - Success' in log and 'Images Verified' in log,log[-5000:]
    code='''from pathlib import Path
import hashlib,json
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
out=Path(%r)
candidate=json.loads(%r)
sha=lambda b:hashlib.sha256(b).hexdigest()
for n,h in candidate.items():assert sha((r/n).read_bytes())==h,n
files={}
for src,dst in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G131-metadata.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G131-metadata.img')]:
 data=(r/src).read_bytes()
 p=out/dst
 with p.open('xb')as f:f.write(data)
 files[dst]={'bytes':len(data),'sha256':sha(data)}
print(json.dumps(files))
'''%(str(w/'private'),json.dumps(candidate))
    r=subprocess.run(['colima','ssh','--','python3','-c',code],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    save(state='built-awaiting-image-audit',files=json.loads(r.stdout),finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    print(json.dumps(status,indent=2))
except BaseException as e:
    save(state='failed',error=str(e)[-9000:])
    raise
