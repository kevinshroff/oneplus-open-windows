"""Recover saved G31 data without another hardware or debugger operation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, default=Path(__file__).resolve().parent)
W = p.parse_args().work
def raw(name):
    path = W / 'private' / (name + '-debug.txt')
    receipt = json.loads((W / (name + '-capture.json')).read_text())['receipt']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt['sha256']
    return path.read_text(errors='replace').replace('\r\n', '\n'), receipt['sha256']
original, original_sha = raw('power-test-02')
projected, projected_sha = raw('projected-v3')
part = projected[projected.rindex('\nG31_PROJECTED_V3_BEGIN\n'):]
assert '\nG31_PROJECTED_V3_END\n' in part
infos = [json.loads(x[len('G31_PROJECTED_INFO '):]) for x in part.splitlines() if x.startswith('G31_PROJECTED_INFO ')]
chunks = [json.loads(x[len('G31_PROJECTED_CHUNK '):]) for x in part.splitlines() if x.startswith('G31_PROJECTED_CHUNK ')]
assert len(infos) == 1
info = infos[0]
assert [c['index'] for c in chunks] == list(range(info['parts']))
text = ''.join(c['text'] for c in chunks)
assert len(text) == info['serialized_bytes']
q = json.loads(text)
assert q['native_reads'] == 588 and q['native_write_attempts'] == 129
assert len(q['events']) == 846 and len(q['transactions']) == 9
scope = original[original.rindex('\nG31_POWER_TEST_BEGIN\n'):original.rindex('\nG31_POWER_TEST_END\n')]
line = next(x for x in scope.splitlines() if x.startswith('G31_POWER_TRIAL_JSON '))
prefix = json.loads(line.split('G31_POWER_TRIAL_JSON ', 1)[1].split(',"events":', 1)[0] + '}')
supplement = []
for i, (a, b) in enumerate(zip(q['transactions'], prefix['transactions'])):
    for key in ['error', 'restore_error']:
        if key not in a:
            assert key in b and b[key] is None
            a[key] = None
            supplement.append('transactions[%d].%s' % (i, key))
assert q['transactions'] == prefix['transactions']
reads = [int(x, 16) for x in re.findall(r'^!dd \[uc\] -m ([0-9a-f]+) L1$', scope, re.M)]
writes = [(int(x, 16), int(y, 16)) for x, y in re.findall(r'^!ed \[uc\] ([0-9a-f]+) ([0-9a-f]+)$', scope, re.M)]
assert reads == [e['address'] for e in q['events'] if e['kind'] == 'read']
assert writes == [(e['address'], e['value']) for e in q['events'] if e['kind'] == 'write_attempt']
assert q['success'] is False and q['restored'] is False and q['needs_recovery'] is True
assert not q['rsc_uncertain'] and not q['observer_uncertain']
assert q['restored_client'] == {'voltage': 1800, 'mode': 7, 'enable': 0x80000000}
(W / 'trial/native-result.json').write_text(json.dumps(q, indent=2) + '\n')
report = {'full_original_result_data_recovered_via_typed_host_projection_and_complete_original_prefix': True,
          'projection_log_sha256': projected_sha, 'original_log_sha256': original_sha,
          'chunks': len(chunks), 'serialized_characters': len(text), 'events': 846,
          'native_reads': 588, 'native_write_attempts': 129,
          'all9_transactions_equal_complete_prefix_in_original_log': True,
          'all_native_read_addresses_and_write_address_values_match_original_command_trace': True,
          'null_fields_omitted_by_host_projection_and_supplemented_from_original_prefix': supplement,
          'power_trial_reexecuted': False, 'initial_single_debugLog_limit_characters': 16362,
          'host_array_Count_is_a_method': True, 'plain_host_object_JSON_stringify_was_incomplete': True}
(W / 'retained-capture-verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'full_result_saved': True, 'events': 846, 'reads': 588, 'writes': 129, 'trial_reexecuted': False}))
