#!/usr/bin/env python3
"""Compile the explicit public 35-object owner closure. No link/sign/load."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

W=Path(__file__).resolve().parent
REPO=W.parent.parent
B=W.parent/'G1287-cold-aperture'
sha=lambda data:hashlib.sha256(data).hexdigest()
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True,help='Clang supporting aarch64-pc-windows-msvc')
p.add_argument('--system-include',required=True,type=Path,action='append',
               help='Repeat for WDK km/KMDF, SDK shared/ucrt and MSVC include roots')
p.add_argument('--layout',required=True,choices=['baseline','nonsecure64'])
p.add_argument('--out',type=Path,required=True,help='Fresh external output directory')
p.add_argument('--secvid-zero-stores',action='store_true',help='G1318 isolated four-zero-store option; default off')
a=p.parse_args()
out=a.out.resolve()
if out==REPO or REPO in out.parents:p.error('output must be outside the public repository')
if out.exists() and any(out.iterdir()):p.error('output directory must be empty')
for d in a.system_include:
    if not d.is_dir():p.error(f'missing system header directory: {d}')
out.mkdir(parents=True,exist_ok=True)
inventory=json.loads((W/'OWNER-SOURCES.json').read_text())['objects']
if len(inventory)!=35 or len({r['object'] for r in inventory})!=35:raise RuntimeError('bad inventory')
includes=[B/x for x in ('source/owner','source','source/broker','reference/runtime','reference/inactive/source')]
args=[a.cc,'--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions',
      '-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1',
      '-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A00000C','-D_WIN32_WINNT=0x0A00',
      '-Wall','-Wextra','-Werror','-D_NO_CRT_STDIO_INLINE',
      '-DOGO_GPU_NONSECURE64_VA='+str(int(a.layout=='nonsecure64'))]
if a.secvid_zero_stores:args+=['-DOGO_GPU_SECVID_ZERO_STORES=1']
for x in includes:args+=['-I'+str(x)]
for x in a.system_include:args+=['-isystem',str(x.resolve())]
compiler_version=subprocess.run([a.cc,'--version'],check=True,text=True,capture_output=True).stdout.splitlines()[0]
rows=[]
for r in inventory:
    src=(B/r['source']).resolve()
    if B.resolve() not in src.parents or not src.is_file():raise RuntimeError('source outside closure or absent')
    obj=out/r['object']
    # Assembly intentionally preserves its historical minimal compile flags.
    command=([a.cc,'--target=aarch64-pc-windows-msvc'] if src.suffix=='.S' else args)
    q=subprocess.run(command+['-c',str(src),'-o',str(obj)],text=True,capture_output=True)
    if q.returncode or q.stderr:
        raise RuntimeError(f"{r['source']}: exit {q.returncode}\n{q.stderr}")
    data=obj.read_bytes()
    if data[:2]!=bytes.fromhex('64aa'):raise RuntimeError('not ARM64 COFF')
    data=data[:4]+bytes(4)+data[8:];obj.write_bytes(data)
    rows.append(dict(source=r['source'],object=r['object'],sha256=sha(data),
                     source_sha256=sha(src.read_bytes()),
                     historical_coff_match=sha(data)==r['historical_coff_sha256'],
                     historical_source_match=sha(src.read_bytes())==r['historical_source_sha256']))
# Exact historical native policy; only output location is made directory-relative.
policy=json.loads((W/'OWNER-LINK.json').read_text())
libraries=policy['libraries']
(out/'owner-objects.rsp').write_text('\n'.join(r['object'] for r in rows)+'\n')
(out/'owner-libraries.rsp').write_text('\n'.join(libraries)+'\n')
(out/'owner-link.rsp').write_text('\n'.join(policy['options']+
    ['/out:'+policy['output'],'/map:'+policy['map']]+[r['object'] for r in rows]+libraries)+'\n')
# Every public closure file is pinned: headers can affect more than the changed TU.
pins={str(x.relative_to(REPO)):sha(x.read_bytes()) for folder in ('source','reference')
      for x in sorted((B/folder).rglob('*')) if x.is_file()}
report=dict(schema='g1311-public-owner-coff/1',layout=a.layout,secvid_zero_stores=a.secvid_zero_stores,objects=rows,
            source_pins=pins,link_policy_sha256=sha((W/'OWNER-LINK.json').read_bytes()),inventory_sha256=sha((W/'OWNER-SOURCES.json').read_bytes()),
            c_flags=args[1:args.index('-I'+str(includes[0]))],
            system_header_roots_count=len(a.system_include),
            compiler_version=compiler_version,native_evidence=False,linked=False,signed=False,loaded=False,
            historical_coff_matches=sum(r['historical_coff_match'] for r in rows))
(out/'OWNER-COMPILE.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(layout=a.layout,objects=len(rows),historical_coff_matches=report['historical_coff_matches'],
                     mismatches=[r['source'] for r in rows if not r['historical_coff_match']],
                     native_evidence=False,linked=False)))
