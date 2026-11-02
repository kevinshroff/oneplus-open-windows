#!/usr/bin/env python3
"""Parse a privately captured, exact 512 x 40-byte CE2 history file offline."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

RECORDS = 512
STRIDE = 40
RING_BYTES = RECORDS * STRIDE


def parse_ring(raw, cursor, tail=32):
    if len(raw) != RING_BYTES:
        raise ValueError(f'ring must contain exactly {RING_BYTES} bytes')
    if type(cursor) is not int or not 0 <= cursor < RECORDS:
        raise ValueError('cursor must be an integer in 0..511')
    if type(tail) is not int or not 1 <= tail <= RECORDS:
        raise ValueError('tail must be an integer in 1..512')
    records = []
    counts = Counter()
    all_zero_slots = 0
    for index in range(RECORDS):
        slot = raw[index * STRIDE:(index + 1) * STRIDE]
        all_zero = not any(slot)
        event = struct.unpack_from('<I', slot, 4)[0]
        if all_zero:
            all_zero_slots += 1
        else:
            counts[f'{event:08x}'] += 1
        records.append({
            'slot': index,
            'all_zero_bytes': all_zero,
            'sw_index': struct.unpack_from('<H', slot)[0],
            'event_hex': f'{event:08x}',
            # Decimal strings retain all 64 bits in JSON consumers using doubles.
            'time_raw': str(struct.unpack_from('<Q', slot, 8)[0]),
            'descriptor_hex': slot[16:32].hex(),
            'descriptor_nbytes_high16': struct.unpack_from('<I', slot, 16)[0] >> 16,
            'context_hex': f'{struct.unpack_from("<Q", slot, 32)[0]:016x}',
            'cursor_possibly_incomplete': index == cursor,
        })
    selected = [records[(cursor - tail + 1 + offset) % RECORDS] for offset in range(tail)]
    return {
        'schema': 'G1312-offline-ce2-history/1',
        'ring_sha256': hashlib.sha256(raw).hexdigest(),
        'ring_bytes': len(raw),
        'record_count': RECORDS,
        'record_bytes': STRIDE,
        'cursor_last_reserved': cursor,
        'cursor_possibly_incomplete': True,
        'all_zero_ring': all_zero_slots == RECORDS,
        'all_zero_slots': all_zero_slots,
        'event_counts_nonzero_physical_slots': dict(sorted(counts.items())),
        'tail_rows': selected,
        'limits': [
            'Cursor is last reserved, not next free. Cursor zero alone does not establish empty state or a wrap.',
            'Tail follows physical slots in reservation order ending at cursor; it is not clock order or a proven complete generation.',
            'Cursor row may be incomplete. Other rows are not independently certified complete; stable metadata alone does not certify writes completed.',
            'All-zero slots are reported as bytes, not proof that a slot was never written. Counts cover nonzero physical slots, not lifetime event totals.',
            'Time is a raw shared-time value, not UTC. No target liveness, loaded identity, capture admission or causation is established.',
            'Event 00000030 records the zero-length branch; its descriptor is re-read later and can contain nonzero length.',
        ],
    }


def decimal(value):
    try:
        return int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError('decimal integer required') from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ring', required=True, type=Path, help='external private 20480-byte capture')
    parser.add_argument('--cursor', required=True, type=decimal, help='actual metadata cursor, decimal 0..511')
    parser.add_argument('--tail', type=decimal, default=32, help='rows ending at cursor, decimal 1..512 (default 32)')
    args = parser.parse_args()
    try:
        # Bound the read as well as rejecting shorter/longer captures.
        with args.ring.open('rb') as stream:
            raw = stream.read(RING_BYTES + 1)
        output = parse_ring(raw, args.cursor, args.tail)
    except (OSError, ValueError) as error:
        parser.exit(2, f'UNQUALIFIED: {error}\n')
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
