"""Execute the actual driver against explicit WDF/OS/sensor-boundary models."""
from pathlib import Path
import argparse,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--sanitizer',default='address,undefined',choices=['address,undefined','thread']);a=p.parse_args();w=Path(__file__).resolve().parent.parent;o=a.output.resolve();o.mkdir(exist_ok=False)
d=(w/'source/driver.c').read_text()
for n in ['ntifs.h','wdf.h','aux_klib.h']:d=d.replace('#include <'+n+'>','')
d=d.replace('#include "identity.inc"','')
(o/'model.c').write_text((w/'tests/driver-model.h').read_text()+'\n'+d+'\n'+(w/'tests/driver-main.c').read_text())
prefix=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize='+a.sanitizer,'-pthread','-I'+str(w/'source'),'-I'+str(w/'core')]
cmds=[prefix+['-DS183Capture=S183ActualCapture','-c',str(w/'source/sensor.c'),'-o',str(o/'sensor.o')],prefix+[str(o/'model.c'),str(o/'sensor.o'),str(w/'source/resources.c'),str(w/'source/os_identity.c'),*[str(w/'core'/(n+'.c'))for n in ['g102_core','g104_core','g111_core']],'-o',str(o/'test')]]
for i,cmd in enumerate(cmds):
 r=subprocess.run(cmd,capture_output=True,text=True);(o/('compiler%d.txt'%i)).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test'),str(a.fixture.resolve())],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
v=json.loads(r.stdout);v.update(source_sha256={str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['source','core','tests']for f in(w/d).iterdir()if f.is_file()},sanitizer=a.sanitizer,fixture_sha256=hashlib.sha256(a.fixture.read_bytes()).hexdigest(),limits=['Actual PnP/timer/worker/status C logic executes; sensor acquisition is an explicit fixture-producing boundary. The actual sensor/cores have their own register models.','WDF,OS identity,physical mapping and scheduling primitives are modeled. Native primitive/allocation/hardware behavior remains separate.']);(o/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v for k,v in v.items()if k!='source_sha256'})
