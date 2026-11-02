"""Compile exact read-only consumer and shared transport with ARM64 WDK."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--toolchain-receipt',type=Path,required=True);args=a.parse_args();w=Path(__file__).resolve().parent;o=args.output.resolve();o.mkdir(exist_ok=False)
prefix=json.loads(args.toolchain_receipt.read_text())['argv'];prefix=prefix[:prefix.index('-c')];prefix=[x for x in prefix if not x.startswith('-I')]+['-I'+str(w/'source')];objects=[]
for name in ['driver','provider_io','health_capture']:
 out=o/(name+'.obj');r=subprocess.run(prefix+['-c',str(w/'source'/(name+'.c')),'-o',str(out)],capture_output=True,text=True);(o/(name+'-compiler.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
 b=out.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;out.write_bytes(b[:4]+bytes(4)+b[8:]);objects.append({'object':out.name,'sha256':hashlib.sha256(out.read_bytes()).hexdigest()})
v={'passed':True,'objects':objects,'compile_prefix':prefix,'sources':{f.name:hashlib.sha256(f.read_bytes()).hexdigest()for f in(w/'source').iterdir()if f.is_file()},'native_operations':0};(o/'compile.json').write_text(json.dumps(v,indent=2)+'\n');print({'passed':True,'objects':objects})
