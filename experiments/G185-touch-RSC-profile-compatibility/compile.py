from pathlib import Path
import argparse,json,hashlib,subprocess,struct
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--toolchain-receipt',type=Path,required=True);args=a.parse_args();w=Path(__file__).resolve().parent;s=w/'source';o=args.output.resolve();o.mkdir(exist_ok=False)
base=json.loads(args.toolchain_receipt.read_text());cmd=base['objects'][0]['argv'];cmd=cmd[:cmd.index('-c')];cmd=[x for x in cmd if not x.startswith('-I')]+['-I'+str(s/'inputs'),'-I'+str(s)];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();objects=[]
for item in base['objects']:
 name=item['source'];f=o/(Path(name).stem+'.obj');r=subprocess.run(cmd+['-c',str(s/name),'-o',str(f)],capture_output=True,text=True);(o/(Path(name).stem+'-compiler.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
 b=f.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;f.write_bytes(b[:4]+bytes(4)+b[8:]);objects.append({'source':name,'source_sha256':sha(s/name),'object':f.name,'sha256':sha(f),'bytes':f.stat().st_size})
headers={name:sha(s/name)for name in sorted(set(base['headers'])|{p.name for p in s.glob('*.h')})};changed=[x['source']for x,y in zip(objects,base['objects'])if x['source_sha256']!=y['source_sha256']]
assert set(changed)=={'g98_hardware.c','g98_rsc.c'},changed
v={'passed':True,'ARM64_objects':len(objects),'objects':objects,'headers':headers,'binding_sha256':sha(s/'inputs/g98_binding.h'),'changed_C_sources':changed,'unchanged_C_objects_byte_identical':[x['object']for x,y in zip(objects,base['objects'])if x['sha256']==y['sha256']],'compile_prefix':cmd,'source_sha256':{str(f.relative_to(w)):sha(f)for f in [*[s/x['source']for x in objects],*[s/n for n in headers],s/'inputs/g98_binding.h',s/'OpenG98.inf']},'native_operations':0};(o/'compile.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in ['passed','ARM64_objects','changed_C_sources','unchanged_C_objects_byte_identical']})
