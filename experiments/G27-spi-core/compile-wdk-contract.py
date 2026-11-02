"""Compile the real NT/WDF headers and core for ARM64, with no installation."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--kits',type=Path,required=True);p.add_argument('--msvc-include',type=Path,required=True)
p.add_argument('--output',type=Path,required=True);p.add_argument('--clang',default='clang');a=p.parse_args()
w=Path(__file__).resolve().parent;assert not a.output.exists();a.output.mkdir(parents=True)
includes=[a.kits/'wdk/c/Include/10.0.26100.0/km',a.kits/'wdk/c/Include/wdf/kmdf/1.15',
          a.kits/'sdk/c/Include/10.0.26100.0/shared',a.kits/'sdk/c/Include/10.0.26100.0/ucrt',a.msvc_include]
assert all(p.is_dir() for p in includes)
base=[a.clang,'--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions',
      '-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1',
      '-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A000000','-D_WIN32_WINNT=0x0A00','-Wall','-Wextra','-Werror']
for path in includes:base+=['-isystem',str(path.resolve())]
base+=['-I'+str(w)]
records=[]
for name in ['wdk-contract','geni_fifo']:
    obj=a.output/(name+'.obj');cmd=base+['-c',str(w/(name+'.c')),'-o',str(obj)]
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
    (a.output/(name+'.txt')).write_text(r.stdout+r.stderr)
    assert r.returncode==0,(name,r.stdout+r.stderr)
    b=obj.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64
    normalized=b[:4]+b'\0'*4+b[8:];(a.output/(name+'-timestamp0.obj')).write_bytes(normalized)
    records.append({'source':name+'.c','source_sha256':hashlib.sha256((w/(name+'.c')).read_bytes()).hexdigest(),
        'object_bytes':len(b),'normalized_sha256':hashlib.sha256(normalized).hexdigest(),'argv':cmd,'exit_code':r.returncode})
receipt={'phase':'ARM64_kernel_header_compile_passed; driver_link_and_native_runtime_unqualified',
         'toolchain':'Apple Clang17 + Microsoft WDK/SDK26100.6584 + existing MSVC14.29 root headers',
         'official_Microsoft_supported_full_build_environment_claimed':False,
         'header_inputs':{n:hashlib.sha256((path/n).read_bytes()).hexdigest()
             for path,n in [(includes[0],'ntddk.h'),(includes[0],'wdm.h'),(includes[1],'wdf.h'),(includes[4],'excpt.h')]},
         'objects':records,'linked_or_installed_driver':False,'native_MMIO_executed':False}
(a.output/'kernel-header-compile.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'ARM64_kernel_objects':len(records),'native_MMIO_executed':False,'receipt':str(a.output/'kernel-header-compile.json')},indent=2))
