"""Retain Go parser results and build the exact ARM64 fixed client."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
parser=argparse.ArgumentParser();parser.add_argument('--revision',choices=['r2'],required=True);args=parser.parse_args()
w=Path(__file__).resolve().parent;p=w.parent/'private';state=p/'reader-verification-r2.json'
assert not state.exists()
q=subprocess.run(['go','test','-count=1','-json','g158_decode.go','g158_decode_test.go','request.go','request_test.go'],cwd=w,capture_output=True,text=True)
(p/'reader-tests-r2.jsonl').write_text(q.stdout);(p/'reader-tests-r2.stderr').write_text(q.stderr)
assert q.returncode==0,q.stdout[-3500:]+q.stderr
events=[json.loads(s)for s in q.stdout.splitlines()];names=[e['Test']for e in events if e['Action']=='run'and 'Test'in e]
leaf=[n for n in names if not any(v.startswith(n+'/')for v in names)]
env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0',GOWORK='off')
argv=['go','build','-trimpath','-buildvcs=false','-ldflags=-buildid=','-o',str((p/'G158-client-r2.exe').resolve()),'main_windows.go','guard_windows.go','g158_decode.go','request.go']
q=subprocess.run(argv,cwd=w,env=env,capture_output=True,text=True);assert q.returncode==0,q.stdout+q.stderr
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
result={'passed':True,'leaf_cases':len(leaf),'cases':leaf,'actual_C_producer_fixtures':3,'actual_C_request_fixtures':2,'exe_sha256':sha(p/'G158-client-r2.exe'),'source_sha256':{str(f.relative_to(w)):sha(f)for f in w.rglob('*')if f.is_file()and(f.suffix in ['.go','.bin']or f.name=='go.mod')},'native_operations':0,'limits':['Actual-C wire/request fixtures and damaged/false completion refusals; no native G158 corrected client execution yet.']}
state.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k not in ['source_sha256','cases']},indent=2))
