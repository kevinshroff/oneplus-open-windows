"""Rebuild the new caller and recheck policy; no phone/controller access."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--previous-cancel',type=Path,required=True);p.add_argument('--previous-idle',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True);expected=json.loads((a.evidence/'caller-build.json').read_text())
def run(name,*args):
 q=subprocess.run([sys.executable,str(W/name),*map(str,args)],capture_output=True,text=True);assert not q.returncode,(q.stdout,q.stderr)
run('build-helper.py','--profile','idle','--output',a.output/'idle-caller');actual=json.loads((a.output/'idle-caller/build.json').read_text())
for key in ['source_files_sha256','binary_sha256','bytes','Go_version','target','cancellation_input_expectation']:assert actual[key]==expected[key],key
run('test-policy.py','--output',a.output/'policy','--previous-cancel',a.previous_cancel,'--previous-idle',a.previous_idle);t=json.loads((a.output/'policy/tests.json').read_text());assert t['passed']
v={'passed':True,'idle_caller_rebuild_byte_identical':True,'caller_sha256':actual['binary_sha256'],'policy_cases':t['cases'],'native_operations':0};(a.output/'source-reproduction.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
