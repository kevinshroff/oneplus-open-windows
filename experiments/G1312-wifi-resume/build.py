#!/usr/bin/env python3
"""Offline G1295 rebuild. Writes only into an explicit, new local output directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'experiments/G1295-wifi-fault-epoch'
NAMES = ('main_windows.go', 'guard.go', 'phase.go')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    output = args.out.resolve() / 'G1295-FaultEpoch-amd64.exe'
    env = dict(os.environ, GOOS='windows', GOARCH='amd64', CGO_ENABLED='0', GOWORK='off')
    cmd = ['go', 'build', '-trimpath', '-ldflags=-buildid=', '-o', str(output), *NAMES]
    sources = {str((SOURCE / name).relative_to(ROOT)): hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() for name in NAMES}
    subprocess.run(cmd, cwd=SOURCE, env=env, check=True)
    if sources != {str((SOURCE / name).relative_to(ROOT)): hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() for name in NAMES}:
        raise RuntimeError('Sources changed during build; discard output')
    receipt = {'schema': 'G1312-offline-build/1', 'target': 'windows/amd64', 'cgo': False,
               'go_version': subprocess.check_output(['go', 'version'], text=True).strip(),
               'source_sha256': sources, 'binary': output.name,
               'binary_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
               'native_inert_check_performed': False, 'hardware_execution_performed': False}
    (args.out / 'BUILD-RECEIPT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))

if __name__ == '__main__':
    main()
