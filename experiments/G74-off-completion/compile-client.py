"""Compile the small native ARM64 client without a C runtime dependency."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--kits',type=Path,required=True);p.add_argument('--msvc',type=Path,required=True);p.add_argument('--user-sdk',type=Path,required=True);p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
includes=[a.user_sdk/'um',a.kits/'sdk/c/Include/10.0.26100.0/shared',a.kits/'sdk/c/Include/10.0.26100.0/ucrt',a.msvc];assert all(p.is_dir()for p in includes)
cmd=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fno-builtin','-fms-extensions','-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_WIN32_WINNT=0x0A00','-DWINVER=0x0A00','-Wall','-Wextra','-Werror','-I'+str(a.binding.resolve()),'-I'+str(W.resolve())]
for d in includes:cmd+=['-isystem',str(d.resolve())]
rows=[]
for name in ['g74_client_windows','g74_client_policy']:
 out=a.output/(name+'.obj');q=subprocess.run([*cmd,'-c',str(W/(name+'.c')),'-o',str(out)],capture_output=True,text=True);(a.output/(name+'-compiler.txt')).write_text(q.stdout+q.stderr);assert not q.returncode,(q.stdout,q.stderr);b=out.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;out.write_bytes(b[:4]+bytes(4)+b[8:]);rows.append({'source':name+'.c','source_sha256':sha(W/(name+'.c')),'object':out.name,'bytes':out.stat().st_size,'sha256':sha(out)})
r={'objects':rows,'headers':{n:sha(W/n)for n in ['g74_client_policy.h','g74_protocol.h','g74_power.h','g74_observer.h']},'binding_sha256':sha(a.binding/'g74_binding.h'),'user_sdk_extraction_sha256':sha(a.user_sdk/'extraction.json'),'target':'aarch64-pc-windows-msvc','no_native_operations':True};(a.output/'compile.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
