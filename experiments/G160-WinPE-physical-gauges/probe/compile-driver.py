"""Compile the fixed handshake and core with the pinned ARM64 WDK headers."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
w = Path(__file__).resolve().parent
out = args.output.resolve()
out.mkdir(exist_ok=False, parents=True)
old = w.parents[1] / 'charging-G135'
baseline = json.loads((old / 'private/compile-02/compile.json').read_text())
prefix = [s.replace(str(old / 'probe'), str(w)) for s in baseline['argv']]
prefix = prefix[:prefix.index('-c')]
objects = []
for name in ['g102_core', 'g104_core', 'g160_driver']:
    argv = [*prefix, '-c', str(w / (name + '.c')), '-o', str(out / (name + '.obj'))]
    q = subprocess.run(argv, capture_output=True, text=True)
    (out / (name + '-compiler.txt')).write_text(q.stdout + q.stderr)
    assert q.returncode == 0, q.stdout + q.stderr
    f = out / (name + '.obj')
    b = f.read_bytes()
    assert struct.unpack_from('<H', b)[0] == 0xaa64
    f.write_bytes(b[:4] + b'\0' * 4 + b[8:])
    objects.append({'source': name + '.c', 'object': f.name,
                    'sha256': hashlib.sha256(f.read_bytes()).hexdigest(), 'bytes': f.stat().st_size})
sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in w.iterdir()
           if p.is_file() and p.suffix in ['.c', '.h', '.inc'] and not p.name.startswith('test-')}
result = {'passed': True, 'objects': objects, 'sources': sources,
          'compile_prefix': prefix, 'native_operations': 0}
(out / 'compile.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
