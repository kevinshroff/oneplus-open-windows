"""Run CPU tests and cross-build the reset helper; never execute it on USB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
source = Path(__file__).resolve().parent / 'sahara-reset'
commands = []

def run(argv, env=None):
    r = subprocess.run(argv, cwd=source, env=env, capture_output=True, text=True,
                       timeout=120)
    commands.append({'argv': argv, 'exit_code': r.returncode,
                     'output': r.stdout + r.stderr})
    if r.returncode:
        (out / 'failed-build.json').write_text(json.dumps(commands, indent=2) + '\n')
        raise RuntimeError('build/test failed; inspect failed-build.json')
    return r.stdout

version = run(['go', 'version']).strip()
run(['go', 'test', '-count=1', '-v', './...'])
exe = out / 'G27-sahara-reset-x64.exe'
env = dict(os.environ, CGO_ENABLED='0', GOOS='windows', GOARCH='amd64', GOAMD64='v1')
run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
     '-o', str(exe), '.'], env)
receipt = {'phase': 'CPU_tests_and_Windows_amd64_cross_build_passed',
           'go_version': version, 'commands': commands,
           'sources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted(source.iterdir()) if p.is_file()},
           'binary_bytes': exe.stat().st_size,
           'binary_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
           'USB_executed_by_this_build_script': False,
           'native_qualified_binary_sha256':
               '81ac71806a6469c8a88bd400958c35ac3882fe6cbbc6e4361cce16c19394db55'}
receipt['byte_identical_to_native_qualified_binary'] = (
    receipt['binary_sha256'] == receipt['native_qualified_binary_sha256'])
(out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['phase', 'binary_bytes', 'binary_sha256']}))
