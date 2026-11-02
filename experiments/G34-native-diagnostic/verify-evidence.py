"""Verify saved native receipts against the independent debugger baseline.

This is an offline evidence check. It submits no target commands and never
loads a driver, maps registers, or changes a service.
"""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[2])
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
R = a.repository
E = R / 'evidence/G34'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text())
n = read(E / 'native-evidence.json')
b = read(E / 'binding.json')
build = read(E / 'build.json')
session = n['phone_session']
assert n['phase'] == 'cycle2_unloaded_service_and_endpoint_absent_control8CPUs'
assert session == read(R / 'evidence/G33/external-post-state.json')['phone_session']
assert len(n['jobs']) == 26
for key, row in n['jobs'].items():
    receipt = row['receipt']
    assert row['id'] == receipt['id'] and receipt['session'] == session
    if key != 'cycle1-selftest':
        assert receipt['status'] == 'ok' and receipt.get('exit_code', 0) == 0

def result(label):
    r = n['jobs'][label]['receipt']
    out = json.loads(r['output'])
    assert out['ok']
    return out['result']

baseline = {}
for name in ['independent-RSC-post.json', 'independent-headers-post.json']:
    d = read(R / 'evidence/G33' / name)
    assert d['success'] and d['MMIO_writes'] == 0
    baseline.update({int(x['address'], 16): int(x['value'], 16) for x in d['reads']})
gpio = read(R / 'evidence/G33/external-post-state.json')
for address, values in gpio['GPIO_samples'].items():
    for i, value in enumerate(values):
        baseline[int(address, 16) + 4*i] = value
assert len(baseline) == len(b['fields']) == 50
assert {x['address'] for x in b['fields']} == set(baseline)
for f in b['fields']:
    region = b['ranges'][f['range']]
    assert f['address'] == region['base'] + f['offset']
    assert f['offset'] % 4 == 0 and f['offset'] + 4 <= region['bytes']

def status(s):
    assert (s['size'], s['version'], s['magic'], s['build_id']) == (80, 1, '0x314f52463433474f', 'G34-kmdf-ro-1')
    assert (s['kernel_build'], s['processors'], s['irql'], s['register_count']) == (26100, 8, 0, 50)
    assert (s['firmware_match'], s['firmware_bytes'], s['firmware_status']) == (1, 576, '0x0')

expected_cases = {
    'long-input': 87, 'wrong-size': 87, 'wrong-version': 87,
    'empty-output': 122, 'empty-input': 87, 'short-input': 87,
    'wrong-magic': 87, 'short-status-output': 122,
    'short-snapshot-output': 122, 'unknown-ioctl': 1,
    'exclusive-open': 5, 'anonymous-open': 5,
}
cycles = []
for number in (1, 2):
    label = 'cycle%d' % number
    load = result(label + '-load')
    assert load['start_success'] and load['state'] == 4 and load['service_created']
    assert load['driver_sha256'] == n['driver_sha256']
    probe = result(label + '-probe')
    status(probe)
    assert probe['map_calls'] == 0 and probe['sequence'] == 1
    tests = result(label + '-selftest-v2')
    status(tests['status'])
    assert tests['passed'] and tests['map_calls_before'] == tests['map_calls_after'] == 0
    assert len(tests['cases']) == 12
    assert {x['case']: x['expected_error'] for x in tests['cases']} == expected_cases
    assert all(x['no_output_bytes'] for x in tests['cases'][:10])
    samples = []
    for sample in ('A', 'B'):
        r = result(label + '-snapshot-' + sample)
        status(r['status'])
        assert r['fixed_register_reads'] == len(r['values']) == 50 and r['register_writes'] == 0
        assert [int(x['address'], 16) for x in r['values']] == [x['address'] for x in b['fields']]
        assert {int(x['address'], 16): x['value'] for x in r['values']} == baseline
        samples.append(r['status'])
    assert [s['map_calls'] for s in samples] == [4, 8]
    assert samples[1]['sequence'] > samples[0]['sequence'] > tests['status']['sequence']
    assert samples[1]['interrupt_time'] > samples[0]['interrupt_time'] > tests['status']['interrupt_time']
    assert result(label + '-stop') == {'delete_requested': True, 'stopped': True}
    assert result(label + '-absent') == {'device_absent': True, 'service_absent': True}
    health = n['jobs'][label + '-post-probe']['receipt']['detail']
    assert health['cpus'] == 8 and health['arch'] == 'arm64'
    cycles.append({'cycle': number, 'guard_checks': 12, 'snapshots': 2,
                   'fixed_reads_per_snapshot': 50, 'all_values_match_G33': True,
                   'map_counts': [4, 8], 'service_and_endpoint_absent': True,
                   'post_control8CPUs': True})

old = n['jobs']['cycle1-selftest']['receipt']
assert old['status'] == 'error' and old['exit_code'] == 1
old_output = json.loads(old['output'])
assert not old_output['ok'] and len(old_output['result']) == 10
assert 'exclusive open: CreateFile: Access is denied.' == old_output['error']
fix = read(E / 'client-native-fix.json')
assert fix['incorrect_expected_exclusive_error'] == 32 and fix['observed_exclusive_open_error'] == 5
assert build['client_v1']['output_sha256'] == fix['original_client_sha256']
assert build['client_v2']['output_sha256'] == build['client_v2_repeated']['output_sha256'] == n['client_sha256'] == fix['corrected_client_sha256']
assert build['compiler']['object_sha256'] == build['compiler_repeated']['object_sha256']
X = R / 'experiments/G34-native-diagnostic'
assert sha(X / 'g34_driver.c') == build['compiler']['source_sha256']
assert sha(X / 'g34_protocol.h') == build['compiler']['protocol_sha256']
assert sha(X / 'g34_client.go') == build['client_v2']['source_sha256']
assert sha(E / 'binding.json') == build['client_v2']['binding_sha256']
links = read(E / 'link-evidence.json')
assert links['link-01']['link']['receipt']['exit_code'] == 1120
assert links['link-02']['link']['receipt']['exit_code'] == 0
assert links['link-02']['output_sha256'] == links['repeated']['hash_receipt']['sha256']
signature = read(E / 'signature-verification.json')
assert signature['signed_driver_sha256'] == n['driver_sha256']
assert signature['unsigned_driver_sha256'] == links['link-02']['output_sha256']
assert signature['SHA256_Authenticode_digest_matches_verified_CMS_content']
assert signature['all_loadable_sections_byte_identical_before_after_signing']
assert not signature['root_trust_store_changed'] and not signature['production_trust_or_WHQL_claimed']
screen = read(E / 'final-screen.json')['receipt']
assert screen['status'] == 'ok' and screen['session'] == session
report = {
    'passed': True, 'phone_session': session, 'cycles': cycles,
    'native_guard_checks': 24, 'native_fixed_register_reads': 200,
    'driver_unloaded_final': True, 'native_boot_or_partition_write': False,
    'original_client_v1_failure_preserved': True,
    'initial_link_failure_preserved': True, 'final_source_build_hashes_match': True,
    'native_screen_sha256': screen['sha256'],
    'PMIC_status_bit6_resolved': False,
    'scope': 'Saved native receipt/source consistency; no new target execution.',
    'limits': ['Temporary fixed-read non-PnP diagnostic, not a bus or regulator owner.',
               'Test environment has existing TestMode and attached kernel debugger.',
               'Working touch and production driver signing remain unqualified.'],
}
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ['passed', 'native_guard_checks', 'native_fixed_register_reads', 'driver_unloaded_final']}))
