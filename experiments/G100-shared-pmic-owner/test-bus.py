"""Run the actual native gate and both portable clients on one aliased MMIO model."""
from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent
(o/'ntddk.h').write_text((w/'test-bus-kernel.h').read_text())
exe=o/'test';sources=['g100_bus.c','g100_bus.h','g98_observer.c','g98_observer.h','g99_core.c','g99_core.h','test-bus.c','test-bus-kernel.h']
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-pthread','-I',str(o),'-I',str(w),str(w/'test-bus.c'),str(w/'g98_observer.c'),str(w/'g99_core.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in sources};(o/'tests.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
