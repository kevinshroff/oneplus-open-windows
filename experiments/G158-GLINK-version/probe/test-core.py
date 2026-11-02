"""Actual-C GLINK negotiation tests, seeded with the retained native G156 bytes."""
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
p = w.parents[1] / 'charging-G156/private'
native = json.loads((p / 'passive-analysis.json').read_text())
assert native['G155_report_sha256'] == 'dd01f054f42d7a1d19e3fdfe8b32b4def8226d88bbf074e5230156cf60dbe70b'
assert native['native_R2_matches_offline_decode'] and native['observer_retired_and_independently_absent']
descriptor = (p / 'sample-1-item-478.bin').read_bytes()
frame = (p / 'sample-1-item-480.bin').read_bytes()[:8]
assert descriptor == struct.pack('<8I', 0, 0, 0, 8, 0, 0, 0, 0)
assert frame == bytes.fromhex('0000010007000000')
(out / 'native-g156.h').write_text('static const uint32_t NativeDescriptor[8]={' +
    ','.join(str(v) for v in struct.unpack('<8I', descriptor)) + '};\n' +
    'static const uint8_t NativeFrame[8]={' + ','.join(str(v) for v in frame) + '};\n')
argv = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-g', '-O1',
        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
        '-I' + str(out), '-I' + str(w), str(w / 'g158_core.c'), str(w / 'test-core.c'),
        '-o', str(out / 'test-core')]
q = subprocess.run(argv, capture_output=True, text=True)
(out / 'compiler.txt').write_text(q.stdout + q.stderr)
assert q.returncode == 0, q.stdout + q.stderr
q = subprocess.run([str(out / 'test-core')], capture_output=True, text=True)
(out / 'run.txt').write_text(q.stdout + q.stderr)
assert q.returncode == 0, q.stdout + q.stderr
result = json.loads(q.stdout)
result.update(source_sha256={n: hashlib.sha256((w / n).read_bytes()).hexdigest()
                           for n in ['g158_core.c', 'g158_core.h', 'test-core.c']},
              actual_G156_capture_sha256=native['capture_sha256'],
              models=['coherent SMEM snapshots and writes', 'asynchronous DSP peer',
                      'MMIO doorbell callback', 'pre/post-store failure boundaries'],
              limits=['No native DSP/GLINK request or kernel driver. Peer/OS/callback behavior is modeled.'])
(out / 'tests.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
