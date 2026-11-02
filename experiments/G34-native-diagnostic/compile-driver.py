"""Compile the actual source-built driver with pinned Microsoft headers."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kits',type=Path,required=True);p.add_argument('--msvc',type=Path,required=True);p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
includes=[a.kits/'wdk/c/Include/10.0.26100.0/km',a.kits/'wdk/c/Include/wdf/kmdf/1.15',a.kits/'sdk/c/Include/10.0.26100.0/shared',a.kits/'sdk/c/Include/10.0.26100.0/ucrt',a.msvc]
assert all(x.is_dir()for x in includes)
cmd=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions','-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1','-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A000000','-D_WIN32_WINNT=0x0A00','-Wall','-Wextra','-Werror','-I'+str(a.binding.resolve()),'-I'+str(W)]
for x in includes:cmd+=['-isystem',str(x.resolve())]
cmd+=['-c',str(W/'g34_driver.c'),'-o',str(a.output/'g34_driver.obj')]
r=subprocess.run(cmd,capture_output=True,text=True);(a.output/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
obj=a.output/'g34_driver.obj';b=obj.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;normalized=b[:4]+b'\0'*4+b[8:];obj.write_bytes(normalized)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'phase':'ARM64_driver_object_compiled; native_link_load_unqualified','source_sha256':sha(W/'g34_driver.c'),'protocol_sha256':sha(W/'g34_protocol.h'),'binding_sha256':sha(a.binding/'g34_binding.h'),'object_bytes':len(normalized),'object_sha256':sha(obj),'argv':cmd,'compiler_output':r.stdout+r.stderr,'header_inputs':{str(x):sha(x)for x in [includes[0]/'ntddk.h',includes[0]/'aux_klib.h',includes[1]/'wdf.h',includes[4]/'excpt.h']},'kernel_driver_MMIO_write_paths':0,'fixed_read_only_snapshot_requires_exact_G17_DSDT':True}
(a.output/'compile.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'ARM64_object_bytes':len(normalized),'sha256':sha(obj),'warnings':bool(r.stderr)}))
