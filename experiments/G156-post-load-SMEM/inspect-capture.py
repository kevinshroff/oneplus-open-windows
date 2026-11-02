"""Offline inspection only: reuse the corrected G135 and G108 format readers."""
from pathlib import Path
import ast
import hashlib
import json
import re
import struct
import subprocess

w = Path(__file__).resolve().parent
p = w / 'private'
load = lambda name: json.loads((p / name).read_text())
sha = lambda data: hashlib.sha256(data).hexdigest()
raw = (p / 'native-capture.bin').read_bytes()
intent = load('intent-capture.json')
receipt = load('capture-receipt.json')
client = json.loads(receipt['output'])
assert receipt['status'] == 'ok' and client['ok'] and intent['complete']
assert len(raw) == 5243168 and sha(raw) == client['sha256'] == intent['capture_sha256']
assert raw[8:16] == b'OG135MR1' and struct.unpack_from('<Q', raw, 80)[0] == int(intent['nonce'], 16)
probe = w.parent / 'charging-G135/probe'
q = subprocess.run(['go', 'run', 'main_offline.go', 'g135_decode.go',
                    str((p / 'native-capture.bin').resolve()), intent['nonce']],
                   cwd=probe, capture_output=True, text=True)
assert q.returncode == 0, q.stderr
decoded = json.loads(q.stdout)
assert decoded == client['result'], 'Independent offline decode differs from native R2'
assert decoded['operation_code'] == 0 and decoded['complete_mask'] == 31 and decoded['maps'] == 10
(p / 'decoded-native-r2.json').write_text(json.dumps(decoded, indent=2) + '\n')
regions = []
for row in decoded['regions']:
    off, n = row['offset'], row['bytes']
    first = raw[288 + off:288 + off + n]
    second = raw[288 + off + n:288 + off + 2 * n]
    assert len(first) == len(second) == n
    assert sha(first) == row['first_sha256'] and sha(second) == row['second_sha256']
    regions.append((row, first, second))

source = (w.parent / 'charging-G108/inspect-capture.py').read_text()
nodes = [n for n in ast.parse(source).body
         if isinstance(n, ast.FunctionDef) and n.name in ['partition', 'smp2p']]
assert len(nodes) == 2
ns = {'struct': struct, 'sha': sha}
exec(compile(ast.Module(body=nodes, type_ignores=[]), 'G108-item-format-functions', 'exec'), ns)

tables, snapshots = [], []
for sample in [1, 2]:
    toc = regions[1][sample]
    assert toc[:4] == b'$TOC' and struct.unpack_from('<I', toc, 4)[0] == 1
    count = struct.unpack_from('<I', toc, 8)[0]
    assert 0 < count <= 64
    table = []
    for i in range(count):
        off, n, flags, h0, h1, cl = struct.unpack_from('<IIIHHI', toc, 32 + 48 * i)
        table.append({'offset': off, 'bytes': n, 'flags': flags,
                      'host0': h0, 'host1': h1, 'cacheline': cl})
    tables.append(table)
    parts = []
    for row, first, second in regions[3:]:
        entries = [e for e in table if e['offset'] == int(row['address'], 16) - 0x81d00000
                   and e['bytes'] == row['bytes'] and (e['host0'], e['host1']) == (row['host0'], row['host1'])]
        assert len(entries) == 1
        parsed = ns['partition']((first, second)[sample - 1], entries[0])
        byid = {item['id']: item for item in parsed['items']}
        candidates = {}
        for ident in [429, 443]:
            if ident in byid:
                try:
                    candidates[str(ident)] = ns['smp2p'](byid[ident]['data'])
                except (AssertionError, struct.error):
                    candidates[str(ident)] = {'format_valid': False}
        descriptor = None
        if 478 in byid and len(byid[478]['data']) == 32:
            descriptor = {'words': list(struct.unpack('<8I', byid[478]['data'])),
                          'transport_ownership_qualified': False}
        for item in parsed['items']:
            if item['id'] in [478, 479, 480]:
                (p / ('sample-' + str(sample) + '-item-' + str(item['id']) + '.bin')).write_bytes(item['data'])
            item.pop('data')
        parts.append({'address': row['address'], 'host0': row['host0'], 'host1': row['host1'],
                      'complete_inventory': True, 'free_uncached': parsed['free_uncached'],
                      'free_cached': parsed['free_cached'], 'items': parsed['items'],
                      'SMP2P_candidates': candidates, 'GLINK_descriptor_candidate': descriptor,
                      'TX_FIFO_479_present': 479 in byid, 'RX_FIFO_480_present': 480 in byid})
    snapshots.append(parts)

old = json.loads((w.parent / 'charging-G135/private/passive-analysis.json').read_text())
changes = []
for current in snapshots[0]:
    previous = next(row for row in old['SMEM_selected_partitions']
                    if (row['host0'], row['host1']) == (current['host0'], current['host1']))
    before = {item['id']: item for item in previous['items']}
    after = {item['id']: item for item in current['items']}
    changes.append({'host0': current['host0'], 'host1': current['host1'],
                    'added_items': sorted(after.keys() - before.keys()),
                    'removed_items': sorted(before.keys() - after.keys()),
                    'changed_items': sorted(i for i in before.keys() & after.keys()
                                            if before[i]['sha256'] != after[i]['sha256'])})
log = regions[2][1]
(p / 'retained-firmware-log.bin').write_bytes(log)
strings = [m.group().decode('ascii') for m in re.finditer(rb'[\x20-\x7e]{8,}', log)]
strings += [m.group().decode('utf-16le') for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', log)]
relevant = [s[:400] for s in strings if re.search(r'TzStatus|SmcId|\badsp\b|\bPIL\b|\bSMC\b', s, re.I)
            and not re.search(r'password|token|secret|key\s*[=:]', s, re.I)][:60]
adsp = next(row for row in snapshots[0] if {row['host0'], row['host1']} == {0, 2})
glob = next(row for row in snapshots[0] if row['host0'] == row['host1'] == 0xfffe)
second_adsp = next(row for row in snapshots[1] if {row['host0'], row['host1']} == {0, 2})
before = {item['id']: item for item in adsp['items']}
after = {item['id']: item for item in second_adsp['items']}
temporal_changes = sorted(i for i in before.keys() & after.keys()
                          if before[i]['sha256'] != after[i]['sha256'])
# These are the retained source definitions, not a guessed FIFO word layout.
smem_source = w.parent / 'charging-G108/private/qcom_glink_smem.c'
native_source = w.parent / 'charging-G108/private/qcom_glink_native.c'
for text in ['tx_pipe->tail = &descs[0]', 'tx_pipe->head = &descs[1]',
             'rx_pipe->tail = &descs[2]', 'rx_pipe->head = &descs[3]']:
    assert text in smem_source.read_text()
words = adsp['GLINK_descriptor_candidate']['words']
assert len(words) == 8
for value in words[:4]:
    assert value % 8 == 0 and value < 16384
tx_tail, tx_head, rx_tail, rx_head = words[:4]
rx = (p / 'sample-1-item-480.bin').read_bytes()
rx_pending = (rx_head - rx_tail) % len(rx)
frame = None
if rx_pending == 8:
    wire = (rx + rx)[rx_tail:rx_tail + 8]
    command, parameter1, parameter2 = struct.unpack('<HHI', wire)
    frame = {'bytes': wire.hex(), 'command': command, 'parameter1': parameter1,
             'parameter2': parameter2, 'interpretation': 'unclassified'}
    if command == 0 and parameter1 == 1:
        frame['interpretation'] = 'GLINK VERSION, version 1, advertised features ' + hex(parameter2)
retired = load('intent-retire.json')
absence = json.loads(load('absence-receipt.json')['output'])
assert retired['complete'] and absence['ok'] and absence['service_absent']
r = {'campaign': 'G156', 'evidence_kind': 'native', 'capture_sha256': sha(raw),
     'session': intent['session'],
     'G155_report_sha256': json.loads(load('load-receipt.json')['output'])['G155_report_sha256'],
     'native_duration_ms': (decoded['end_100ns'] - decoded['begin_100ns']) / 10000,
     'physical_bytes_read': decoded['read_bytes'],
     'all_five_regions_match_between_samples': all(a == b for row, a, b in regions),
     'native_R2_matches_offline_decode': True, 'physical_writes': 0, 'PAS_calls_by_G156': 0,
     'SMEM_partition_tables': tables, 'SMEM_snapshots': snapshots,
     'changes_from_G135': changes, 'retained_log_sha256': sha(log),
     'retained_log_relevant_lines': relevant, 'global_item_count': len(glob['items']),
     'ADSP_item_ids': [item['id'] for item in adsp['items']],
     'ADSP_RX_FIFO_480_present': adsp['RX_FIFO_480_present'],
     'AP_ADSP_items_changed_between_samples': temporal_changes,
     'GLINK_ring_state': {'AP_TX_tail': tx_tail, 'AP_TX_head': tx_head,
                          'DSP_TX_tail': rx_tail, 'DSP_TX_head': rx_head,
                          'DSP_pending_bytes': rx_pending, 'frame': frame},
     'protocol_source_sha256': {str(f.name): sha(f.read_bytes())
                                for f in [smem_source, native_source]},
     'observer_retired_and_independently_absent': True,
     'DSP_running_qualified': False, 'GLINK_ready_qualified': False, 'charging_qualified': False,
     'limits': ['Finite passive snapshots do not establish DSP liveness or a charger reply.',
                'Cross-boot differences are observations, not isolation of a single causal change.',
                'Only global and AP/ADSP heaps were read; no other private processor heap.',
                'No PAS retry/shutdown, FIFO-index update or charger command.']}
(p / 'passive-analysis.json').write_text(json.dumps(r, indent=2) + '\n')
print(json.dumps({key: r[key] for key in ['capture_sha256', 'native_duration_ms',
      'physical_bytes_read', 'all_five_regions_match_between_samples', 'global_item_count',
      'ADSP_item_ids', 'ADSP_RX_FIFO_480_present', 'changes_from_G135',
      'retained_log_relevant_lines']}, indent=2))
