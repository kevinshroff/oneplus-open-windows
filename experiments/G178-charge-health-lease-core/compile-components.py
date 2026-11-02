"""Compile policy components and actual-provider ABI with pinned ARM64 WDK.
This does not compile/link/sign the deliberately blocked draft native driver.
"""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--toolchain-receipt',type=Path);a.add_argument('--g160-source',type=Path);a.add_argument('--g167-source',type=Path);args=a.parse_args();w=Path(__file__).resolve().parent;o=args.output.resolve();o.mkdir(exist_ok=False)
receipt=args.toolchain_receipt or w.parent/'charging-G135/private/compile-02/compile.json';g160=args.g160_source or w.parent/'charging-G160/probe';g167=args.g167_source or w.parent/'charging-G167/probe'
prefix=json.loads(receipt.read_text())['argv'];prefix=prefix[:prefix.index('-c')];prefix=[s for s in prefix if not s.startswith('-I')]
prefix+=['-I'+str(w/'link'),'-I'+str(g160),'-I'+str(g167)]
files=[w/'link/link_core.c',w/'link/charger_codec.c',w/'link/health_capture.c',w/'link/health_monitor.c',w/'tests/provider-layout.c'];objects=[]
for f in files:
 out=o/(f.stem+'.obj');r=subprocess.run(prefix+['-c',str(f),'-o',str(out)],capture_output=True,text=True);(o/(f.stem+'-compiler.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
 b=out.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;out.write_bytes(b[:4]+bytes(4)+b[8:]);objects.append({'source':str(f.relative_to(w)),'object':out.name,'sha256':hashlib.sha256(out.read_bytes()).hexdigest()})
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();v={'passed':True,'scope':'Compile-only policy plus actual provider ABI; no deployable native adapter yet.','ARM64_provider_ABI_assertions':17,'objects':objects,'source_sha256':{str(f.relative_to(w)):sha(f)for f in [*files,*sorted((w/'link').glob('*.h'))]},'compile_prefix':prefix,'native_operations':0}
(o/'compile.json').write_text(json.dumps(v,indent=2)+'\n');print({'passed':True,'objects':len(objects),'actual_ARM64_provider_ABI_assertions':17,'native_operations':0})
