"""Execute the actual bounded clock core, with ordinary/ambiguous faults."""
from pathlib import Path
import argparse, hashlib, json, subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
W=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True)
exe=a.output/'clock-model'
q=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(W),str(W/'test-clock.c'),str(W/'g67_clock.c'),'-o',str(exe)],capture_output=True,text=True)
assert not q.returncode,(q.stdout,q.stderr)
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr)
v=json.loads(q.stdout);v.update(source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in ['g67_clock.c','g67_clock.h','g67_protocol.h','test-clock.c']},sanitizers=['AddressSanitizer','UndefinedBehaviorSanitizer'])
(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
