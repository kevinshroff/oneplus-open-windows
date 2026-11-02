"""Build/reproduce the separate RAM updater; retain hashes and real test output."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess

W=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path('/path/to/user/Documents/GitHub/oneplusopen-win11/maintenance/disktool'));p.add_argument('--output',type=Path,required=True);a=p.parse_args()
src=a.source.resolve();out=a.output.resolve();assert not out.exists();out.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=sorted([*src.glob('*.go'),src/'go.mod'])
sources={p.name:sha(p)for p in files}
old=W.parent/'gpio-G21/updater-build-receipt.json'
if not old.exists():old=W.parents[1]/'evidence/G65/updater-r5-source-baseline.json'
prior=json.loads(old.read_text())['sources']
assert all(sources[n]==h for n,h in prior.items()if n!='main_windows.go'),'Previously qualified helpers changed'
dispatch='\tif a[0] == "update-trial-wim-ram" && len(a) == 4 && a[3] == "--update-only-inactive-trial-file-from-ram" {\n\t\treturn updateTrialWIMFromRAM(a[1], a[2])\n\t}\n'
main=(src/'main_windows.go').read_text();assert main.count(dispatch)==1
assert hashlib.sha256(main.replace(dispatch,'').encode()).hexdigest()==prior['main_windows.go'],'Old CLI dispatch changed'
version=subprocess.check_output(['go','version'],text=True).strip();assert 'go1.26.4 'in version
q=subprocess.run(['go','test','-count=1','-json','./...'],cwd=src,capture_output=True,text=True)
(out/'tests.jsonl').write_text(q.stdout)
assert q.returncode==0,q.stderr
tests=[json.loads(line)for line in q.stdout.splitlines()]
assert tests[-1]['Action']=='pass'
env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
exe=out/'G65-disktool-r6.exe'
argv=['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',str(exe),'.']
q=subprocess.run(argv,cwd=src,env=env,capture_output=True,text=True)
assert q.returncode==0,(q.stdout,q.stderr)
assert sources=={p.name:sha(p)for p in files}
m={'Go_version':version,'target':'windows/arm64','CGO_ENABLED':'0','argv':argv,'sources_sha256':sources,'binary_sha256':sha(exe),'bytes':exe.stat().st_size,'passed_tests':sum(t['Action']=='pass'and'Test'in t for t in tests),'previous_qualified_helpers_unchanged_except_new_CLI_dispatch':True,'physical_root_updater_source_unchanged':True,'native_operations':0}
(out/'build.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps({k:m[k]for k in ['binary_sha256','bytes','passed_tests','physical_root_updater_source_unchanged']}),flush=True)
