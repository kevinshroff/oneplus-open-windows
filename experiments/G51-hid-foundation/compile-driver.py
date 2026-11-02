"""Compile the ARM64 PnP input foundation with pinned WDK/MSVC headers."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--kits',type=Path,required=True);p.add_argument('--msvc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
includes=[a.kits/'wdk/c/Include/10.0.26100.0/km',a.kits/'wdk/c/Include/wdf/kmdf/1.15',a.kits/'sdk/c/Include/10.0.26100.0/shared',a.kits/'sdk/c/Include/10.0.26100.0/ucrt',a.msvc]
assert all(x.is_dir()for x in includes);cmd=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions','-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1','-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A000000','-D_WIN32_WINNT=0x0A00','-Wall','-Wextra','-Werror','-I'+str(W)]
for x in includes:cmd+=['-isystem',str(x.resolve())]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();rows=[]
for name in ['g51_driver','g51_report']:
 src=W/(name+'.c');out=a.output/(name+'.obj');argv=cmd+['-c',str(src),'-o',str(out.resolve())];q=subprocess.run(argv,capture_output=True,text=True);(a.output/(name+'-compiler.txt')).write_text(q.stdout+q.stderr);assert not q.returncode,q.stderr
 b=out.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;out.write_bytes(b[:4]+b'\0'*4+b[8:]);rows.append({'source':src.name,'source_sha256':sha(src),'object':out.name,'bytes':out.stat().st_size,'sha256':sha(out),'argv':argv})
(a.output/'compile.json').write_text(json.dumps({'objects':rows,'headers':{n:sha(W/n)for n in ['g51_baseline.h','g51_protocol.h','g51_report.h']},'no_MMIO_or_raw_storage_API_in_source':True,'native_device_enumeration_qualified':False},indent=2)+'\n');print(json.dumps({'objects':[{k:r[k]for k in['object','bytes','sha256']}for r in rows]}))
