"""Compile the fixed observer against supplied licensed WDK/MSVC headers."""
import argparse, hashlib, json, struct, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['kits','msvc','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);w=Path(__file__).resolve().parent
includes=[a.kits/'wdk/c/Include/10.0.26100.0/km',a.kits/'wdk/c/Include/wdf/kmdf/1.15',a.kits/'sdk/c/Include/10.0.26100.0/shared',a.kits/'sdk/c/Include/10.0.26100.0/ucrt',a.msvc]
assert all(x.is_dir()for x in includes)
cmd=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions','-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1','-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A000008','-D_WIN32_WINNT=0x0A00','-Wall','-Wextra','-Werror','-I'+str(w),'-I'+str(w)]
for x in includes:cmd+=['-isystem',str(x.resolve())]
obj=a.output/'g116_driver.obj';cmd+=['-c',str(w/'g116_driver.c'),'-o',str(obj)]
r=subprocess.run(cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(r.stdout+r.stderr)
assert r.returncode==0,r.stdout+r.stderr
assert struct.unpack_from('<H',obj.read_bytes())[0]==0xaa64
b=obj.read_bytes();obj.write_bytes(b[:4]+bytes(4)+b[8:])
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
m={'argv':cmd,'object_sha256':sha(obj),'COFF_timestamp_normalized_to_zero':True,'sources':{n:sha(w/n)for n in ['g116_driver.c','g116_plan.h','g116_protocol.h','g116_binding.h','guard-and-status.inc','lifecycle.inc']},'native_hardware_access':False}
(a.output/'compile.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps({'object_sha256':m['object_sha256']}))
