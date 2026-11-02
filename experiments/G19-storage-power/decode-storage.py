"""Verify the captured read/write tests and bounded native GIC/UFS snapshots."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re

W = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('physical', W.parent/'platform-snapshot/decode-physical.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
read_result = json.loads((W/'read-load-result.json').read_text())
s = read_result['output']
iterations = list(re.finditer(r'(?m)^G19_READ_ITERATION (\d+)\r?$', s))
assert [int(x[1]) for x in iterations] == list(range(1, 13))
sha = 'f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'
for x in iterations:
    v = json.JSONDecoder().raw_decode(s[x.end():].lstrip())[0]
    assert v['target']['Name'] == 'boot_a' and v['raw_writes'] == 0
    assert v['access'] == 'GENERIC_READ' and v['bytes'] == 201326592 and v['sha256'] == sha
assert read_result['status'] == 'ok' and read_result['exit_code'] == 0
assert 'G19_READ_LOOP_COMPLETE' in s
snap = json.loads((W/'live-io-snapshots.json').read_text())
log = W.parent/'platform-snapshot/private'/snap['source_log']
assert hashlib.sha256(log.read_bytes()).hexdigest() == snap['sha256']
for tag, values in snap['snapshots'].items():
    parts = m.section(log.read_text(errors='replace'), tag)
    assert len(parts) == 1
    words = m.words(parts[0])
    assert all(words[int(a, 16)] == v for a, v in values.items())
job = json.loads((W/'scratch-put-job.json').read_text())
put = json.loads((W/'scratch-put-result.json').read_text())
append = json.loads((W/'scratch-append-result.json').read_text())
filehash = json.loads((W/'scratch-filehash-result.json').read_text())
for d in [put, append, filehash]:
    assert d['status'] == 'ok' and d['exit_code'] == 0
assert put['sha256'] == job['sha256']
v = json.JSONDecoder().raw_decode(append['output'].lstrip())[0]
assert v['chunk_sha256'] == job['sha256'] and v['chunk_bytes'] == job['bytes'] and v['offset'] == 0
v = json.JSONDecoder().raw_decode(filehash['output'].lstrip())[0]
assert v['sha256'] == job['sha256'] and v['bytes'] == job['bytes']
probe = json.loads((W/'post-test-probe.json').read_text())
assert probe['status'] == 'ok' and probe['session'] == read_result['session']
r = {
    'read_test': json.loads((W/'read-test-verification.json').read_text()),
    'live_registers': snap,
    'scratch_write_test': {
        'put_job': put['id'], 'put_duration_ms': put['duration_ms'],
        'flushed_copy_job': append['id'], 'flushed_copy_duration_ms': append['duration_ms'],
        'readback_job': filehash['id'], 'bytes_per_file': job['bytes'], 'sha256': job['sha256'],
        'raw_partition_writes': 0,
        'scope': 'ordinary scratch files; agent also durably journals its incoming signed job; not a raw super update',
    },
    'post_test_probe': {'job': probe['id'], 'session': probe['session'], 'version': probe['detail']['version'], 'cpus': probe['detail']['cpus']},
    'limit': 'Serial read and write tests passed. Earlier concurrent write stall was not reproduced or fixed. Register reads are sequential and debugger-perturbed.',
}
(W/'storage-test-summary.json').write_text(json.dumps(r, indent=2)+'\n')
print('Verified 12 partition hashes, three register snapshots, scratch upload/flushed copy/readback and post-test native control')
