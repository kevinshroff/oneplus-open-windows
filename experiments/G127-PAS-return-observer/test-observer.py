"""Replay original SCM outputs through the new portable diagnostic core."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--replay',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(exist_ok=False);w=Path(__file__).resolve().parent
r=json.loads(a.replay.read_text());assert r['passed']and r['native_operations']==0
fixtures=[]
for case in r['results']:
 for c in case['SCM_calls']:
  cmd=int(c['command'],16)
  if cmd not in [0x42000201,0x42000202,0x42000205]:continue
  args=[int(x,16)for x in c['arguments']];res=[int(x,16)for x in c['results']];status=int(c['status'],16)
  fixtures.append({'ABI':1 if case['ABI_fixture']=='legacy'else 2,'command':cmd,'param':int(c['param_id'],16),'image':args[0],'args':args[:3],'status':status,'results':res,'good':status==0 and res[0]==1 and res[1]==0})
assert fixtures
h='typedef struct { unsigned ABI,Command,Param,Image; unsigned long long Arg1,Arg2,Status,Result[4];unsigned Good;}Fixture;\nstatic const Fixture Fixtures[]={\n'
for f in fixtures:
 vals=[f['ABI'],f['command'],f['param'],f['image'],f['args'][1],f['args'][2],f['status']]
 h+='{'+','.join(hex(v)+'ULL'for v in vals)+',{'+','.join(hex(v)+'ULL'for v in f['results'])+'},'+str(int(f['good']))+'},\n'
h+='};\n';(a.output/'fixtures.h').write_text(h)
cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),'-I',str(a.output),str(w/'OpenPasObserver.c'),str(w/'test-pas-observer.c'),'-o',str(a.output/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stdout+x.stderr
x=subprocess.run([str((a.output/'test').resolve())],capture_output=True,text=True);assert x.returncode==0 and not x.stderr,(x.stdout,x.stderr)
result=json.loads(x.stdout);result['original_replay_sha256']=hashlib.sha256(a.replay.read_bytes()).hexdigest();result['sources']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenPasObserver.c','OpenPasObserver.h','test-pas-observer.c','test-observer.py']}
(a.output/'tests.json').write_text(json.dumps(result,indent=2)+'\n')
obj=a.output/'OpenPasObserver.obj'
cmd=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fno-builtin','-fno-stack-protector','-std=c11','-O2','-Wall','-Wextra','-Werror','-c',str(w/'OpenPasObserver.c'),'-o',str(obj)]
x=subprocess.run(cmd,capture_output=True,text=True);(a.output/'ARM64-compiler.txt').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stdout+x.stderr
b=obj.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;obj.write_bytes(b[:4]+bytes(4)+b[8:]);result['ARM64_COFF_compile']=True;result['ARM64_object_sha256']=hashlib.sha256(obj.read_bytes()).hexdigest()
ptr,count=struct.unpack_from('<II',b,8);at=ptr;undefined=[]
while at<ptr+18*count:
 row=b[at:at+18];section=struct.unpack_from('<h',row,12)[0]
 if section==0 and row[16]==2:undefined.append(row[:8].hex())
 at+=18*(1+row[17])
assert not undefined,undefined
result['undefined_external_symbols']=undefined
(a.output/'tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
