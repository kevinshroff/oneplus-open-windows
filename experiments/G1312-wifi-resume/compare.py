#!/usr/bin/env python3
"""Offline comparison of corrected G1295 results; never accesses a target."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def need(ok, why):
    if not ok:
        raise ValueError(why)


def load(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def result(path, phase):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    need(bool(rows), 'empty result')
    first = rows[0]
    need(first.get('phase') == 'begin', 'missing result begin')
    identity = ('boot_id', 'phone_session', 'image_sha256', 'root_nonce', 'action_ledger_sha256')
    need(type(first.get('boot_id')) is int and first['boot_id'] > 161, 'old/missing boot')
    for key, size in [('phone_session', 32), ('root_nonce', 32), ('image_sha256', 64), ('action_ledger_sha256', 64)]:
        need(re.fullmatch('[0-9a-f]{%d}' % size, first.get(key, '')) is not None, 'missing/invalid ' + key)
    for row in rows:
        need(all(row.get(key) == first[key] for key in identity), 'mixed result identity')
        need(row.get('observation_phase') == phase, 'wrong observation phase')
    need(sum(row.get('phase') == 'begin' for row in rows) == 1, 'concatenated result')
    need(sum(row.get('phase') == 'phase_consumed_before_debugger_connect' for row in rows) == 1, 'missing/duplicate consumed phase')
    terminal = [row for row in rows if row.get('phase') in ('complete_held', 'refused_or_failed')]
    need(len(terminal) == 1 and terminal[0] == rows[-1], 'missing/duplicate/nonterminal outcome')
    last = rows[-1]
    if last['phase'] == 'refused_or_failed':
        return first, None
    need(last.get('status_EE_stable') is True, 'MHI state/EE changed during phase; no qualified comparison')
    need(last.get('MHI_status_raw') == last.get('MHI_status_after') and last.get('EE_raw') == last.get('EE_after'), 'inconsistent stable flag')
    values = [last.get('BHI_error_code_raw')] + last.get('BHI_error_debug_raw', [])
    need(len(values) == 4 and all(type(v) is int and 0 <= v < 0xffffffff for v in values), 'unavailable/incomplete error tuple')
    # This checks recorded observations; held CPU and stable MHI status do not freeze Q6.
    for label, value in zip(('BHI_ERRCODE', 'BHI_ERRDBG1', 'BHI_ERRDBG2', 'BHI_ERRDBG3'), values):
        reads = [r for r in rows if r.get('phase') == 'unforced_fault_read' and r.get('label') == label]
        need(len(reads) == 1, 'missing/duplicate tuple read: ' + label)
        read = reads[0]
        need(read.get('hresult') == '00000000' and read.get('actual_bytes') == 4 and read.get('raw_hex') == value.to_bytes(4, 'little').hex(), 'tuple read mismatch: ' + label)
    return first, values


def compare(pre_path, post_path, ledger_path, marker_path):
    pre, before = result(pre_path, 'PRE_HOST_INIT')
    post, after = result(post_path, 'POST_STALL')
    need(all(pre[key] == post[key] for key in ('boot_id', 'phone_session', 'image_sha256')), 'PRE/POST boot/session/image mismatch')
    need(pre['root_nonce'] != post['root_nonce'], 'phase nonce reused')
    ledger = load(ledger_path)
    marker = load(marker_path)
    need(digest(ledger_path) == post['action_ledger_sha256'], 'POST ledger hash mismatch')
    need(ledger.get('pre_phase_result_sha256') == digest(pre_path), 'PRE result not bound to POST ledger')
    need(ledger.get('pre_phase_marker_sha256') == digest(marker_path), 'PRE marker not bound to POST ledger')
    need(marker.get('schema') == 'G1295-host-phase-once/1' and marker.get('phase') == 'PRE_HOST_INIT', 'wrong PRE marker schema/phase')
    need(ledger.get('schema') == 'G1295-actual-boot-action-ledger/1' and ledger.get('phase') == 'POST_STALL', 'wrong POST ledger schema/phase')
    for key in ('boot_id', 'phone_session', 'image_sha256'):
        need(marker.get(key) == pre[key] and ledger.get(key) == post[key], 'artifact identity mismatch: ' + key)
    need(marker.get('root_nonce') == pre['root_nonce'] and marker.get('action_ledger_sha256') == pre['action_ledger_sha256'], 'PRE marker/result mismatch')
    if before is None or after is None:
        decision = 'NO_BASELINE_OR_POST_READ: no epoch comparison; do not replace refusal with zeros'
    elif before == after:
        decision = 'SAME_OBSERVED_TUPLE: weakens assignment to this init/scan interval; prioritize fresh CE/HTC receive-credit evidence'
    else:
        decision = 'CHANGED_OBSERVED_TUPLE: change lies between observations; review init/scan log chronology before selecting one transport discriminator'
    return {'schema': 'G1312-offline-pair/1', 'decision': decision,
            'pre_tuple_hex': None if before is None else ['%08x' % v for v in before],
            'post_tuple_hex': None if after is None else ['%08x' % v for v in after],
            'limits': 'Sequential MMIO observations, not atomic Q6 snapshots. No assertion semantics, exact failing command, or networking success follows. Admission remains the operator responsibility.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pre-result', 'post-result', 'post-ledger', 'pre-marker'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        value = compare(args.pre_result, args.post_result, args.post_ledger, args.pre_marker)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(2, 'UNQUALIFIED: ' + str(error) + '\n')
    print(json.dumps(value, indent=2))

if __name__ == '__main__':
    main()
