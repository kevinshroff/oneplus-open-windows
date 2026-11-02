#!/usr/bin/env python3
"""Compile the actual C core, native adapter and generated ABI checks for ARM64."""
import argparse,hashlib,json,pathlib,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--toolchain-receipt',type=pathlib.Path,required=True);a=p.parse_args()
w=pathlib.Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
prefix=json.loads(a.toolchain_receipt.read_text())['argv'];prefix=prefix[:prefix.index('-c')]
prefix=[s for s in prefix if not s.startswith('-I')]+['-I'+str(w/'link'),'-I'+str(w/'native')]
objects=[]
for f in [w/'link/link_core.c',w/'link/charger_codec.c',w/'native/driver.c']:
 target=o/(f.stem+'.obj');r=subprocess.run(prefix+['-c',str(f),'-o',str(target)],capture_output=True,text=True)
 (o/(f.stem+'-compiler.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
 b=target.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;target.write_bytes(b[:4]+b'\0'*4+b[8:])
 objects.append({'object':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
result={'passed':True,'objects':objects,'compile_prefix':prefix,'sources':{str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['native','link']for f in sorted((w/d).iterdir())if f.is_file()},'native_operations':0}
(o/'compile.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(objects,indent=2))
