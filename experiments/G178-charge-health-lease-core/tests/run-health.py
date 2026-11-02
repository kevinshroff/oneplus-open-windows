"""Actual C consumer over saved G177 physical captures; no new phone calls."""
from pathlib import Path
import argparse,hashlib,json,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--captures',type=Path);args=a.parse_args();w=Path(__file__).resolve().parent.parent;o=args.output.resolve();o.mkdir(exist_ok=False)
old=args.captures.resolve()if args.captures else w.parent/'charging-G177/private';pairs=[]
for phase in ['before-fv','after-fv']:pairs.append([old/(phase+'-G167-raw.bin'),old/(phase+'-G160-raw.bin')])
for phase in ['initial-off','enabled-early','enabled-late','after-final-off']:pairs.append([old/('cycle-'+phase+'-G167.bin'),old/('cycle-'+phase+'-G160.bin')])
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w/'link'),str(w/'tests/test-health.c'),str(w/'link/health_capture.c'),'-o',str(o/'test-health')]
r=subprocess.run(cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test-health'),*[str(f)for p in pairs for f in p]],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stdout+r.stderr
v=json.loads(r.stdout);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();v['sources']={str(f.relative_to(w)):sha(f)for f in [w/'link/health_capture.c',w/'link/health_capture.h',w/'link/health_layout.h',w/'tests/test-health.c',Path(__file__).resolve()]};v['input_sha256']={str(f):sha(f)for p in pairs for f in p};(o/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in ['passed','cases','frozen_native_pairs','native_operations']})
