"""Validate the existing PMIC/pin/RSC capture; never issue a target command."""
from pathlib import Path
import argparse
import hashlib
import json
import re

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, default=Path(__file__).resolve().parent)
W = p.parse_args().work
path = W / 'private/pmic-baseline-debug.txt'
raw = path.read_text(errors='replace').replace('\r\n', '\n')
receipt = json.loads((W / 'pmic-baseline-capture.json').read_text())['receipt']
assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt['sha256']
part = raw[raw.rindex('\nG30_PMIC_BASELINE_BEGIN\n'):]
assert '\nG30_PMIC_BASELINE_END\n' in part
def result(marker):
    rows = [json.loads(t[len(marker):]) for t in part.splitlines() if t.startswith(marker)]
    assert len(rows) == 1
    return rows[0]
q = result('G30_PMIC_OBSERVER_JSON ')
assert q['read_commands'] == 5 and q['pmic_write_commands'] == q['configuration_writes'] == 0
assert len(q['targets']) == 3 and all(not t['error'] for t in q['targets'])
ldo = next(t for t in q['targets'] if t['ppid'] == 0x1c4)
assert ldo['identity'] == [0, 4, 1, 1, 4, 0xab, 0, 0]
assert ldo['configuration'] == [8, 7, 0, 0, 7, 7, 0, 0] and ldo['status'] == [3]
for event in q['events']:
    if event['kind'] == 'observer_read_command':
        assert event['command'] >> 27 == 1
shadow = result('G29_RSC_SHADOW_JSON ')
assert shadow['success'] and shadow['MMIO_writes'] == 0
assert shadow['values'] == json.loads((W / 'mode/native-result.json').read_text())['after']
pins = {}
for address in [0xf10a000, 0xf118000]:
    pattern = r'^\s*#\s*' + format(address, 'x') + r'\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s*$'
    matches = re.findall(pattern, part, re.M)
    assert len(matches) == 1
    pins[hex(address)] = [int(x, 16) for x in matches[0]]
assert pins == {'0xf10a000': [1, 0], '0xf118000': [0x201, 0]}
sha = hashlib.sha256(path.read_bytes()).hexdigest()
(W / 'native-PMIC-baseline.json').write_text(json.dumps(q, indent=2) + '\n')
(W / 'native-post-queries-shadow.json').write_text(json.dumps({
    'phone_session': '00000000000000000000000000000000',
    'native_result': shadow, 'raw_log_sha256': sha}, indent=2) + '\n')
(W / 'native-pins-baseline.json').write_text(json.dumps({
    'pins': pins, 'raw_log_sha256': sha, 'MMIO_writes': 0}, indent=2) + '\n')
print(json.dumps({'PMIC_LDO4_VSET_mV': 1800, 'MODE': 7, 'EN_CTL': 0,
                  'STATUS': 3, 'GPIO10': [1, 0], 'GPIO24': [513, 0],
                  'independent_RSC_shadow_matches': True}))
