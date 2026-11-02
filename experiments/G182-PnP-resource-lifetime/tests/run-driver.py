"""Execute actual PnP adapter with explicit WDF/OS/mapping models."""
from pathlib import Path
import argparse,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--sanitizer',choices=['address,undefined','thread'],default='address,undefined');a=p.parse_args();w=Path(__file__).resolve().parent.parent;o=a.output.resolve();o.mkdir(exist_ok=False)
d=(w/'source/driver.c').read_text()
for n in ['ntifs.h','wdf.h','aux_klib.h']:d=d.replace('#include <'+n+'>','')
(o/'model.c').write_text((w/'tests/driver-model.h').read_text()+'\n'+d+'\n'+(w/'tests/driver-main.c').read_text())
r=subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize='+a.sanitizer,'-pthread','-I'+str(w/'source'),str(o/'model.c'),str(w/'source/resources.c'),'-o',str(o/'test-driver')],capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test-driver')],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
v=json.loads(r.stdout);v.update(sanitizer=a.sanitizer,source_sha256={str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['source','tests']for f in(w/d).iterdir()if f.is_file()},limits=['WDF,OS identity/resource delivery,mapping and mutex behavior are modeled.','Actual C callback logic is executed; no native driver,firmware publication,physical mapping or register access.']);(o/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print({k:x for k,x in v.items()if k!='source_sha256'})
