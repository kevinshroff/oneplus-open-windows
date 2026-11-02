"""Run actual continuous sensor adapter/cores with explicit fixed-register models."""
from pathlib import Path
import ast,argparse,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent.parent;o=a.output.resolve();o.mkdir(exist_ok=False)
# Self-contained explicit register models, derived from the pinned G160/G167 models.
code=(w/'tests/register-model.h').read_text()+(w/'tests/sensor-main.c').read_text()
(o/'model.c').write_text(code)
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined','-I'+str(w/'source'),'-I'+str(w/'core'),str(o/'model.c'),str(w/'source/sensor.c'),*[str(w/'core'/(n+'.c'))for n in ['g102_core','g104_core','g111_core']],'-o',str(o/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test'),str(o/'success.bin')],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
v=json.loads(r.stdout);v.update(source_sha256={str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['source','core','tests']for f in(w/d).iterdir()if f.is_file()},sanitizer='address,undefined',limits=['Actual sensor adapter and unchanged fixed-read cores execute. MMIO/register transitions,clock,stall and cancellation are explicit models.','No native access,resource/power readiness or driver lifetime is established by these models.']);(o/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v for k,v in v.items()if k!='source_sha256'})
