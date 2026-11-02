#!/usr/bin/env python3
"""Compile only the changed production owner TU in both layouts; no link/load/sign."""
import argparse, hashlib, json, subprocess
from pathlib import Path
W=Path(__file__).resolve().parent
B=W.parent/'G1287-cold-aperture'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True,help='Clang supporting aarch64-pc-windows-msvc')
p.add_argument('--system-include',required=True,type=Path,action='append',
               help='Repeat for locally acquired WDK km/KMDF, SDK shared/ucrt, MSVC headers')
p.add_argument('--out',type=Path,required=True)
a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
for directory in a.system_include:
    if not directory.is_dir():p.error(f'missing header directory: {directory}')
includes=[B/x for x in ('source/owner','source','source/broker','reference/runtime','reference/inactive/source')]
args=[a.cc,'--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions',
      '-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1',
      '-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A00000C','-D_WIN32_WINNT=0x0A00',
      '-D_NO_CRT_STDIO_INLINE','-Wall','-Wextra','-Werror']
for x in includes:args+=['-I'+str(x)]
for x in a.system_include:args+=['-isystem',str(x.resolve())]
src=B/'source/owner/gpu_cp_native.c';rows=[]
# Missing option is deliberately tested separately from explicit zero.
for name,flag in (('default',[]),('baseline',['-DOGO_GPU_NONSECURE64_VA=0']),
                  ('nonsecure64',['-DOGO_GPU_NONSECURE64_VA=1'])):
    obj=out/f'gpu_cp_native-{name}.obj'
    subprocess.run(args+flag+['-c',str(src),'-o',str(obj)],check=True)
    data=obj.read_bytes()
    if data[:2]!=bytes.fromhex('64aa'):raise RuntimeError('not ARM64 COFF')
    obj.write_bytes(data[:4]+bytes(4)+data[8:])
    rows.append(dict(layout=name,object=obj.name,sha256=hashlib.sha256(obj.read_bytes()).hexdigest()))
assert rows[0]['sha256']==rows[1]['sha256'],'default drift'
assert rows[1]['sha256']!=rows[2]['sha256'],'opt-in did not affect emitted owner'
report=dict(native_evidence=False,linked=False,signed=False,loaded=False,objects=rows,
            source=str(src.relative_to(W.parent.parent)),source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),
            header_sha256=hashlib.sha256((B/'source/owner/gpu_va_layout.h').read_bytes()).hexdigest())
(out/'COFF-RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
