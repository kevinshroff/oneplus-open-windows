"""Execute the actual bounded clock core, with ordinary/ambiguous faults."""
from pathlib import Path
import argparse, hashlib, json, subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--native-fixture',type=Path,required=True);a=p.parse_args()
W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True)
exe=a.output/'clock-model'
q=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(W),str(W/'test-clock.c'),str(W/'g70_clock.c'),'-o',str(exe)],capture_output=True,text=True)
assert not q.returncode,(q.stdout,q.stderr)
assert a.native_fixture.stat().st_size==1872 and hashlib.sha256(a.native_fixture.read_bytes()).hexdigest()=='532c8f21e9a54d8543aab458f62fea9b14408691336e2080454d3552d145e42a'
q=subprocess.run([str(exe),str(a.native_fixture)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr)
v=json.loads(q.stdout);v.update(source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in ['g70_clock.c','g70_clock.h','g70_protocol.h','test-clock.c']},sanitizers=['AddressSanitizer','UndefinedBehaviorSanitizer'])
v['G68_native_fixture_sha256']=hashlib.sha256(a.native_fixture.read_bytes()).hexdigest()
(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
