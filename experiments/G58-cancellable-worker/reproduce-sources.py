"""Rebuild the exported source and compare all objects/helpers; no phone I/O."""
from pathlib import Path
import argparse, json, subprocess, sys

p = argparse.ArgumentParser()
for name in ['kits', 'msvc', 'expected-build', 'output']:
    p.add_argument('--'+name, type=Path, required=True)
a = p.parse_args()
W = Path(__file__).resolve().parent
assert not a.output.exists()
a.output.mkdir(parents=True)
J = lambda path: json.loads(path.read_text())
expected = J(a.expected_build)
def run(name, *args):
    q = subprocess.run([sys.executable, str(W/name), *map(str, args)], capture_output=True, text=True)
    assert q.returncode == 0, (q.stdout, q.stderr)
run('compile-driver.py', '--kits', a.kits, '--msvc', a.msvc,
    '--binding', W/'inputs', '--output', a.output/'ARM64')
rebuilt = J(a.output/'ARM64/compile.json')
old = expected['ARM64_compilation']
assert rebuilt['headers'] == old['headers'] and rebuilt['binding_sha256'] == old['binding_sha256']
assert [{k: o[k] for k in ['source', 'source_sha256', 'object', 'bytes', 'sha256']} for o in rebuilt['objects']] == [{k: o[k] for k in ['source', 'source_sha256', 'object', 'bytes', 'sha256']} for o in old['objects']]
helpers = {}
for name in ['admin', 'receiver', 'child', 'cleanup']:
    run('build-helper.py', '--name', name, '--output', a.output/name)
    b, e = J(a.output/name/'build.json'), expected['helpers'][name]
    for field in ['source_files_sha256', 'binary_sha256', 'bytes', 'Go_version', 'target']:
        assert b[field] == e[field], (name, field)
    helpers[name] = b['binary_sha256']
report = {'passed': True, 'ARM64_objects_byte_identical': len(rebuilt['objects']),
          'all_protocol_headers_and_binding_equal': True, 'helpers_byte_identical': helpers,
          'native_operations': 0}
(a.output/'source-reproduction.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report))
