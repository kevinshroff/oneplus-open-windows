"""Build a separate exact-image-pair updater; preserve every old helper source."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess

W=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
p.add_argument('--source',type=Path,default=W/'updater-source');a=p.parse_args()
src=a.source.resolve();out=a.output.resolve();assert not out.exists();out.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior=json.loads((W/'updater-source-derivation.json').read_text())['prior_sha256']
files=sorted([*src.glob('*.go'),src/'go.mod']);sources={p.name:sha(p)for p in files}
assert all(sources[n]==h for n,h in prior.items()if n not in ('wim_ram.go','g68_pair_test.go'))
assert set(sources)==(set(prior)-{'g68_pair_test.go'})|{'g70_pair_test.go'}
image=json.loads((W/'WIM-qualified.json').read_text());assert image['both_directions_locally_reconstructed']
policy=(src/'wim_ram.go').read_text()
for h in [image['source_sha256'],image['sha256']]:assert h in policy
assert image['source_sha256']!=image['sha256']
version=subprocess.check_output(['go','version'],text=True).strip();assert 'go1.26.4 'in version
env=dict(os.environ,G70_PLAN_ROOT=str(W))
q=subprocess.run(['go','test','-count=1','-json','./...'],cwd=src,env=env,capture_output=True,text=True)
(out/'tests.jsonl').write_text(q.stdout)
assert q.returncode==0,q.stderr
tests=[json.loads(l)for l in q.stdout.splitlines()];assert tests[-1]['Action']=='pass'
assert not any(t['Action']=='skip' for t in tests)
env.update(GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
exe=out/'G70-disktool-r8.exe';argv=['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',str(exe),'.']
q=subprocess.run(argv,cwd=src,env=env,capture_output=True,text=True);assert q.returncode==0,(q.stdout,q.stderr)
assert sources=={p.name:sha(p)for p in files}
m={'Go_version':version,'target':'windows/arm64','CGO_ENABLED':'0','argv':argv,'sources_sha256':sources,'binary_sha256':sha(exe),'bytes':exe.stat().st_size,'passed_tests':sum(t['Action']=='pass'and'Test'in t for t in tests),'skipped_tests':0,'actual_forward_inverse_proposed_WIM_hashes_tested':True,'old_helpers_and_dispatch_unchanged':True,'only_previous_source_changed':'wim_ram.go fixed image pair pins','physical_root_updater_source_unchanged':True,'native_operations':0}
(out/'build.json').write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({k:m[k]for k in ['binary_sha256','bytes','passed_tests','actual_forward_inverse_proposed_WIM_hashes_tested']}),flush=True)
