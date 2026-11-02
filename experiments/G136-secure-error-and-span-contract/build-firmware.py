"""Build the one-use error diagnostic from the verified native G134 baseline.

Compilation and model results never authorize a device operation. Staging,
image audit, native script validation and a fresh fastboot cue remain required.
"""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess

w = Path(__file__).resolve().parent
source = w / 'private/candidate-source'
lib = Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
sha = lambda b: hashlib.sha256(b).hexdigest()


def gate(path, cases, names=(), field='source_sha256'):
    result = json.loads(path.read_text())
    assert result['passed'] and result['cases'] == cases, path
    for name in names:
        assert result[field][name] == sha((source / lib / name).read_bytes()), (path, name)
    return result


g134 = w.parent / 'charging-G134/private'
gate(g134 / 'footprint-model-01/tests.json', 68,
     ['OpenKernelFootprint.c', 'OpenKernelFootprint.h'])
gate(g134 / 'metadata-probe-model-01/tests.json', 31,
     ['OpenPilMetadataProbe.c', 'OpenPilMetadataProbe.h'])
gate(g134 / 'admission-model-01.json', 18,
     ['OpenDspAdmission.c', 'OpenDspAdmission.h', 'OpenDspAt.c'], 'source_SHA256')
gate(w / 'private/adapter-model-01/tests.json', 59,
     ['OpenGuardedAdsp.c', 'OpenGuardedAdsp.h', 'OpenPasObserver.c',
      'OpenPasObserver.h', 'OpenScmErrorCapture.c', 'OpenScmErrorCapture.h'])
gate(w / 'private/memory-observer-model-01/tests.json', 44,
     ['OpenPasObserver.c', 'OpenPasObserver.h'])
gate(w / 'private/error-capture-model-03/tests.json', 121,
     ['OpenScmErrorCapture.c', 'OpenScmErrorCapture.h'])
for name, cases in [('original-SCM-log-01.json', 23),
                    ('PIL-filtered-return-original-01.json', 4),
                    ('exact-span-original-02.json', 8)]:
    result = gate(w / 'private' / name, cases)
    assert result['native_operations'] == 0
facade = gate(w / 'private/preflight-test-results.json', 33)
assert facade['source_sha256'] == sha((source / lib / 'OpenAdspPreflight.c').read_bytes())
assert facade['native_ReadOnlyBlockIo_sha256'] == 'ca1543c88759e23b42b40fa5578e674351a8f015a38d3a901b968fe5dbc90adc'
assert (w / 'private/reader-tests.txt').read_text().rstrip().splitlines()[-2] == 'PASS'
assert (w / 'private/G136-read-DSP.exe').is_file()

baseline = json.loads((w.parent / 'boot-repair-G80/private/firmware-normal/source-hashes.json').read_text())
for campaign in ['G119', 'G128', 'G131', 'G133', 'G134']:
    baseline.update(json.loads((w.parent / ('charging-' + campaign) / 'private/candidate-source-hashes.json').read_text()))
assert baseline[str(lib / 'ReadOnlyBlockIo.c')] == facade['native_ReadOnlyBlockIo_sha256']
candidate = {str(p.relative_to(source)): sha(p.read_bytes())
             for p in sorted(source.rglob('*')) if p.is_file()}
assert len(candidate) == 23
(w / 'private/candidate-source-hashes.json').write_text(json.dumps(candidate, indent=2) + '\n')
state = w / 'private/build-state.json'
assert not state.exists(), 'Observe the existing build invocation; do not restart it.'
status = {'state': 'preparing', 'pid': os.getpid(),
          'started_UTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'native_phone_operations': 0,
          'changed_sources': sum(candidate[n] != baseline.get(n) for n in candidate),
          'diagnostic': 'Original DTB INIT/MEM_SETUP only, same G134 arguments; forced abort after accepted memory setup; no AUTH/main/retry.'}


def save(**kw):
    status.update(kw)
    state.write_text(json.dumps(status, indent=2) + '\n')


save()
install = '''from pathlib import Path
import hashlib,json,os,subprocess
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');s=Path(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip()=='68ae12fafdcd873240d8635afecac542c2c4c563'
expected=json.loads(%r);candidate=json.loads(%r)
for n,h in expected.items():assert (r/n).is_file() and not(r/n).is_symlink() and sha(r/n)==h,('Baseline',n)
assert sha(r/'Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')=='c0831da8dda3d1d026cc16375e8e2018e2d0f9ba94d4e829e2f6e796e34dd018'
written=0
for n,h in candidate.items():
 assert sha(s/n)==h
 p=r/n
 if n not in expected:assert not p.exists(),('Unexpected pre-existing new source',n)
 if p.exists() and sha(p)==h:continue
 written+=1
 tmp=p.with_name(p.name+'.G136-tmp')
 with tmp.open('xb')as f:f.write((s/n).read_bytes())
 os.replace(tmp,p);assert sha(p)==h
print(json.dumps({'baseline_files':len(expected),'candidate_files':len(candidate),'files_written':written,'native_phone_operations':0}))
''' % (str(source), json.dumps(baseline), json.dumps(candidate))
try:
    result = subprocess.run(['colima', 'ssh', '--', 'python3', '-c', install], capture_output=True, text=True)
    (w / 'private/source-install.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr[-5000:]
    save(state='building', source_install=json.loads(result.stdout))
    command = ('source ~/woa-open/venv/bin/activate && source ~/woa-open/build-env.sh && '
               'cd /home/PROJECT_USER.guest/woa-open/mu_aloha_platforms && '
               'python3 build_uefi.py -d oneplus-open -t DEBUG')
    with (w / 'private/build.log').open('wb') as stream:
        result = subprocess.run(['colima', 'ssh', '--', 'bash', '-lc', command], stdout=stream, stderr=subprocess.STDOUT)
    log = (w / 'private/build.log').read_text(errors='replace')
    assert result.returncode == 0 and 'PROGRESS - Success' in log and '121 Images Verified' in log, log[-6000:]
    collect = '''from pathlib import Path
import hashlib,json
r=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');out=Path(%r);candidate=json.loads(%r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,h in candidate.items():assert sha(r/n)==h,n
files={}
for old,new in [('Build/KailuaPkg/DEBUG_CLANGPDB/FV/SM8550_EFI.fd','G136-memory-diagnostic.fd'),('Build/KailuaPkg/oneplus-open.img','boot-G136-memory-diagnostic.img')]:
 p=out/new
 with p.open('xb')as f:f.write((r/old).read_bytes())
 files[new]={'bytes':p.stat().st_size,'sha256':sha(p)}
print(json.dumps(files))
''' % (str(w / 'private'), json.dumps(candidate))
    result = subprocess.run(['colima', 'ssh', '--', 'python3', '-c', collect], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    save(state='built_awaiting_audit', files=json.loads(result.stdout),
         finished_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat())
    print(json.dumps(status, indent=2))
except BaseException as error:
    save(state='failed', error=str(error)[-9000:])
    raise
