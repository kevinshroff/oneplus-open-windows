"""Audit native poll bytes against complete wire history, without phone I/O."""
from pathlib import Path
import argparse, collections, hashlib, json, struct, subprocess

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('--evidence', type=Path, help='Audit the exported evidence folder directly; uses only Go and saved files.')
a = p.parse_args()
W = Path(__file__).resolve().parent
J = lambda path: json.loads(path.read_text())
checksum = lambda raw: (sum(raw[:-2]) & 65535) == struct.unpack_from('<H', raw, len(raw)-2)[0]
results = {}
for run, suffix in [('idle', ''), ('physical', '-physical')]:
    if a.evidence:
        raw_path = a.evidence / (('physical-' if suffix else 'native-') + 'power.bin')
        q = subprocess.run(['go', 'run', str(W/'g57_hwdecode.go'), str(W/'decode-native.go'), str(raw_path.resolve())], capture_output=True, text=True)
        assert q.returncode == 0 and not q.stderr, (q.returncode, q.stderr)
        d = json.loads(q.stdout)
    else:
        folder = W / ('private/live-native' + suffix + '-01')
        raw_path = folder/'power.bin'
        d = J(folder / 'power-decoded.json')
    poll = d['touch']['poll']
    assert poll['operation_code'] == 0 and poll['cycles'] == poll['limit'] == 100
    assert poll['bus_quiescent'] == 1
    wires = iter(poll['wires'])
    consumed = 0

    def take(kind, address, payload):
        global consumed
        f = next(wires)
        consumed += 1
        assert (f['kind'], int(f['address'], 16), f['payload']) == (kind, address, payload)
        assert f['attempted'] == f['transport_ok'] == 1 and f['state'] == 4
        assert f['start_code'] == f['step_code'] == f['cancel_sent'] == f['abort_sent'] == 0
        count = 6 if kind == 3 else payload + 8
        assert f['tx_done'] == count and f['rx_done'] == (0 if kind == 3 else count)
        expected = bytes.fromhex('f00001027400') if kind == 3 else b'\xf1' + address.to_bytes(4, 'big') + b'\xff\xff\xff' + bytes(payload)
        assert bytes(f['wire_TX']) == expected + bytes(72-len(expected))
        return bytes(f['wire_RX'][8:8+payload])

    retries, recovered, retried_idle = [], 0, 0
    gpio = collections.Counter()
    headers = collections.Counter()
    clears = samples = 0
    for cycle, row in enumerate(poll['records'], 1):
        raw = take(1, 0x10274, 26)
        if row['header_retry']:
            assert raw[0] and not checksum(raw[:8]) and bytes(row['first_raw']) == raw
            assert row['first_read_bytes'] == 26 and row['irq_mask'] == 15
            original = raw
            raw = take(4, 0x10274, 26)
            assert not raw[0] or checksum(raw[:8])
            recovered += bool(raw[0])
            retried_idle += not raw[0]
            retries.append({'cycle': cycle, 'first_raw': original.hex(), 'fresh_prefix': raw.hex(),
                            'first_computed_sum': sum(original[:6]) & 65535,
                            'first_stored_sum': int.from_bytes(original[6:8], 'little'),
                            'differing_prefix_bytes': [{'index': index, 'first': old, 'fresh': new}
                                                       for index, (old, new) in enumerate(zip(original, raw)) if old != new],
                            'invalid_first_snapshot_cleared': False,
                            'fresh_idle': not bool(raw[0]), 'GPIO': row['irq_samples']})
        else:
            assert row['first_read_bytes'] == 0 and row['first_raw'] == [] and row['irq_mask'] == 3
        if row['tail_read']:
            assert raw[0] and checksum(raw[:8]) and raw[2] & 15 > 2
            raw += take(2, 0x1028e, ((raw[2] & 15)-2)*8)
        assert bytes(row['raw_bytes'][:row['read_bytes']]) == raw
        assert row['error'] == 0
        headers['present' if raw[0] else 'idle'] += 1
        if raw[0]:
            assert checksum(raw[:8]) and row['header_checked'] == row['header_valid'] == 1
            if row['kind'] == 3 and row['point_count']:
                assert checksum(raw[8:8+row['point_count']*8+2])
                assert row['body_checked'] == row['body_valid'] == 1
            elif row['kind'] == 3:
                assert row['body_checked'] == row['body_valid'] == 0
        else:
            assert row['kind'] == 1 and row['header_checked'] == row['clear_attempted'] == 0
        if row['clear_attempted']:
            assert row['clear_completed'] == 1 and row['kind'] in (2, 3)
            take(3, 0x10274, 1)
            clears += 1
        for index, sample in enumerate(row['irq_samples']):
            if row['irq_mask'] & (1 << index):
                assert sample['control'] == 0xc0 and sample['config'] == 0xe2
                assert sample['input'] in (0, 1) and sample['status'] in (0, 1)
                samples += 1
                gpio[f"{sample['input']}/{sample['status']}"] += 1
    assert next(wires, None) is None and consumed == poll['wire_count']
    assert clears == poll['clear_attempts'] == poll['clear_completed']
    assert len(retries) == poll['header_retries'] and recovered == poll['headers_recovered']
    assert samples == poll['irq_read_attempts'] == 200 + 2*len(retries)
    results[run] = {'raw_sha256': hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                    'cycles': 100, 'poll_us': poll['elapsed_us'], 'wire_commands': consumed,
                    'header_counts': dict(headers), 'clears': clears, 'retries': retries,
                    'valid_header_recoveries': recovered, 'retry_to_idle': retried_idle,
                    'GPIO_input_status_counts': dict(gpio), 'GPIO_samples': samples,
                    'raw_wire_record_agreement': True, 'all_accepted_nonzero_body_checksums_valid': True}
report = {'passed': True, 'sessions': results,
          'actual_header_recovery_qualified': any(x['valid_header_recoveries'] for x in results.values()),
          'limits': ['GPIO samples do not prove IRQ delivery or establish a readiness gate.',
                     'The cause of a bad header is unproved; no changing-snapshot or electrical cause is claimed.',
                     'Finite episodes do not qualify continuous touch.']}
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report))
