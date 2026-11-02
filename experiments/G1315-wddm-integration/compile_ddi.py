#!/usr/bin/env python3
"""Compile the complete G779 DDI translation unit with external Microsoft headers.

Produces an ARM64 COFF object and dependency/hash receipt, never links or stages.
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
    source = repo / 'drivers/gpu/gpu-wddm-bridge-G779/source/ddi.c'
    a.out.mkdir(parents=True, exist_ok=False)
    out = a.out.resolve()
    argv = [str(compiler), '--target=aarch64-pc-windows-msvc', '-ffreestanding',
            '-fms-extensions', '-fms-compatibility', '-fno-stack-protector',
            '-O2', '-std=c11', '-D_ARM64_=1', '-D_KERNEL_MODE',
            '-DNTDDI_VERSION=0x0A00000C', '-D_WIN32_WINNT=0x0A00',
            '-D_NO_CRT_STDIO_INLINE', '-Wall', '-Wextra', '-Werror']
    for root in roots:
        argv += ['-isystem', str(root)]
    argv += ['-MD', '-MF', str(out / 'ddi.d'), '-c', str(source), '-o', str(out / 'ddi.obj')]
    r = subprocess.run(argv, text=True, capture_output=True)
    (out / 'compile.log').write_text(r.stdout + r.stderr)
    receipt = {'schema': 'G1315-full-ddi-coff/1', 'argv': argv,
               'compiler_sha256': digest(compiler),
               'compiler_version': subprocess.check_output([str(compiler), '--version'], text=True),
               'returncode': r.returncode, 'source_sha256': digest(source),
               'linked': False, 'signed': False, 'loaded': False,
               'scheduler_or_hardware_qualified': False}
    if r.returncode == 0:
        dependencies = (out / 'ddi.d').read_text().replace('\\\n', '')
        paths = shlex.split(dependencies.split(': ', 1)[1])
        receipt['dependencies'] = [{'path': str(Path(x).resolve()), 'sha256': digest(Path(x))}
                                   for x in sorted(set(paths))]
        receipt['object_sha256'] = digest(out / 'ddi.obj')
        receipt['object_bytes'] = (out / 'ddi.obj').stat().st_size
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(out / 'receipt.json')
    raise SystemExit(r.returncode)


if __name__ == '__main__':
    main()
