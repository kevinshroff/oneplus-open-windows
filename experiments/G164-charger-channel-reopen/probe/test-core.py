"""Actual-C channel/intent/query/close state machine with explicit DSP models."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False,parents=True)
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(w/'test-core.c'),str(w/'g164_core.c'),str(w/'g164_codec.c'),'-o',str(o/'test')],capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
q=subprocess.run([str(o/'test')],capture_output=True,text=True);(o/'run.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
r=json.loads(q.stdout);r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g164_core.c','g164_core.h','g164_codec.c','g164_codec.h','test-core.c']};r['models']=['Coherent SMEM rings, host barriers/stores and fixed doorbell','Asynchronous DSP channel/open/close/intent/data peer','Before/after-store callback errors'];r['limits']=['No native GLINK or battery measurement. Message-order variations and peer behavior are explicit models.'];(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
