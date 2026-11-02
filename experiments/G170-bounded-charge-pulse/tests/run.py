#!/usr/bin/env python3
"""Compile and execute actual portable C with an explicit peer and IO failures."""
import argparse,hashlib,json,pathlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
w=pathlib.Path(__file__).resolve().parent.parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=True)
args=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w/'link'),str(w/'tests/test-link.c'),str(w/'link/link_core.c'),str(w/'link/charger_codec.c'),'-o',str(o/'test-link')]
r=subprocess.run(args,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test-link')],capture_output=True,text=True);(o/'test-output.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
result=json.loads(r.stdout);result['source_sha256']={str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['link','tests']for f in sorted((w/d).iterdir())if f.suffix in ['.h','.c','.py']}
result['limits']=['Explicit peer and virtual monotonic time; no native DSP observation, resource ownership or charging measurement.','The caller must serialize this core; WDF adapter lifetime tests are separate.','Local generation is bookkeeping, not a firmware transaction ID.']
(o/'tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
