#!/usr/bin/env python3
"""Compile all 21 G779 KMD units with external Microsoft headers.

Produces ARM64 COFF objects, native-link response input and dependency/hash receipts.
Never links, signs, stages or opens the adapter.
Header roots and compiler are explicit; no SDK/WDK files are shipped here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', type=Path, required=True)
    p.add_argument('--include-dir', type=Path, action='append', required=True,
                   help='External real WDK/SDK/MSVC header root, repeated in search order')
    p.add_argument('--out', type=Path, required=True, help='New exclusive build directory')
    a = p.parse_args()
    roots = [r.resolve(strict=True) for r in a.include_dir]
    if not all(r.is_dir() for r in roots):
        p.error('All include roots must be directories')
    for name in ('ntddk.h', 'dispmprt.h', 'd3dkmddi.h', 'acpiioct.h'):
        if not any((r / name).is_file() for r in roots):
            p.error('Missing real Microsoft display WDK header: ' + name)
    compiler = a.compiler.resolve(strict=True)
    repo = Path(__file__).resolve().parents[2]
    source_root = repo / 'drivers/gpu/gpu-wddm-bridge-G779/source'
    a.out.mkdir(parents=True, exist_ok=False)
    out = a.out.resolve()
    argv = [str(compiler), '--target=aarch64-pc-windows-msvc', '-ffreestanding',
            '-fms-extensions', '-fms-compatibility', '-fno-stack-protector',
            '-O2', '-std=c11', '-D_ARM64_=1', '-D_KERNEL_MODE',
            '-DNTDDI_VERSION=0x0A00000C', '-D_WIN32_WINNT=0x0A00',
            '-D_NO_CRT_STDIO_INLINE', '-Wall', '-Wextra', '-Werror']
    for root in roots:
        argv += ['-isystem', str(root)]
    units = ['a740_hal', 'a740_power', 'hw', 'ddi', 'msm', 'eng', 'disp',
             'log', 'g321_plan', 'g321_runtime', 'g196_preflight', 'g190_backend',
             'vendor/AdrenoFirmware', 'vendor/AdrenoHfiEncode', 'g433_cp',
             'g433_runtime', 'vendor/AdrenoPM4', 'g440_gpu_power', 'g456_hwinit',
             'g482_resources', 'g482_board']
    results = []
    for unit in units:
        source = source_root / (unit + '.c')
        name = unit.replace('/', '_')
        obj = out / (name + '.obj')
        dep = out / (name + '.d')
        command = argv + ['-MD', '-MF', str(dep), '-c', str(source), '-o', str(obj)]
        r = subprocess.run(command, text=True, capture_output=True)
        (out / (name + '.log')).write_text(r.stdout + r.stderr)
        item = {'unit': unit, 'argv': command, 'returncode': r.returncode,
                'source_sha256': digest(source)}
        if r.returncode == 0:
            dependencies = dep.read_text().replace('\\\n', '')
            paths = shlex.split(dependencies.split(': ', 1)[1])
            item['dependencies'] = [{'path': str(Path(x).resolve()), 'sha256': digest(Path(x))}
                                    for x in sorted(set(paths))]
            item['object_sha256'] = digest(obj)
            item['object_bytes'] = obj.stat().st_size
        results.append(item)
    receipt = {'schema': 'G1330-full-kmd-coff/1', 'units': results,
               'compiler_sha256': digest(compiler),
               'compiler_version': subprocess.check_output([str(compiler), '--version'], text=True),
               'all_compiled': all(x['returncode'] == 0 for x in results),
               'linked': False, 'signed': False, 'loaded': False,
               'scheduler_or_hardware_qualified': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    # Deliberately no libraries: caller must select and hash real ARM64 import
    # archives and validate all imports before any native link. No /FORCE.
    response = ['/machine:arm64', '/driver:wdm', '/subsystem:native', '/entry:DriverEntry',
                '/nodefaultlib', '/incremental:no', '/out:topazgpu.sys', '/map:topazgpu.map']
    response += ['"' + unit.replace('/', '_') + '.obj"' for unit in units]
    (out / 'kmd-objects.rsp').write_text('\n'.join(response) + '\n')
    print(out / 'receipt.json')
    raise SystemExit(0 if receipt['all_compiled'] else 1)


if __name__ == '__main__':
    main()
