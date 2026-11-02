"""Compile the resource-only PnP qualifier with the pinned ARM64 WDK."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--toolchain-receipt',type=Path,required=True);args=a.parse_args();w=Path(__file__).resolve().parent;o=args.output.resolve();o.mkdir(exist_ok=False)
cmd=json.loads(args.toolchain_receipt.read_text())['argv'];cmd=cmd[:cmd.index('-c')];cmd=[x for x in cmd if not x.startswith('-I')]+['-I'+str(w/'source'),'-I'+str(w/'core')];objects=[]
for n in ['resources','sensor','driver','g102_core','g104_core','g111_core']:
 f=o/(n+'.obj');r=subprocess.run(cmd+['-c',str(w/('core'if n.endswith('_core')else'source')/(n+'.c')),'-o',str(f)],capture_output=True,text=True);(o/(n+'-compiler.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr;b=f.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;f.write_bytes(b[:4]+bytes(4)+b[8:]);objects.append({'object':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
proof={'passed':True,'objects':objects,'compile_prefix':cmd,'source_sha256':{str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['source','core']for f in(w/d).iterdir()if f.is_file()},'native_operations':0};(o/'compile.json').write_text(json.dumps(proof,indent=2)+'\n');print({'passed':True,'ARM64_objects':len(objects),'native_operations':0})
