"""Synthetic CE history records only; no captured bytes or device operations."""
import struct
import unittest
from parse_ce_history import parse_ring, RECORDS, STRIDE, RING_BYTES


def put(raw, index, sw_index, event, time, nbytes, context=0):
    base = index * STRIDE
    struct.pack_into('<H', raw, base, sw_index)
    struct.pack_into('<I', raw, base + 4, event)
    struct.pack_into('<Q', raw, base + 8, time)
    struct.pack_into('<I', raw, base + 16, (nbytes << 16) | 0x1234)
    struct.pack_into('<Q', raw, base + 32, context)


class HistoryTest(unittest.TestCase):
    def test_zero_branch_with_nonzero_reread_length(self):
        raw = bytearray(RING_BYTES)
        put(raw, 1, 73, 0x30, 2**63 + 7, 144, 0xfedcba9876543210)
        result = parse_ring(raw, 1, 1)
        row = result['tail_rows'][0]
        self.assertEqual(result['event_counts_nonzero_physical_slots'], {'00000030': 1})
        self.assertEqual(row['sw_index'], 73)
        self.assertEqual(row['descriptor_nbytes_high16'], 144)
        self.assertEqual(row['descriptor_hex'][:8], '34129000')
        self.assertEqual(row['time_raw'], str(2**63 + 7))
        self.assertEqual(row['context_hex'], 'fedcba9876543210')
        self.assertTrue(row['cursor_possibly_incomplete'])
        self.assertIn('can contain nonzero length', ' '.join(result['limits']))

    def test_wrap_preserves_reservation_order_not_time(self):
        raw = bytearray(RING_BYTES)
        put(raw, 510, 10, 1, 300, 24)
        put(raw, 511, 11, 0x10, 100, 0)
        put(raw, 0, 12, 0x31, 200, 0)
        result = parse_ring(raw, 0, 3)
        self.assertEqual([r['slot'] for r in result['tail_rows']], [510, 511, 0])
        self.assertEqual([r['time_raw'] for r in result['tail_rows']], ['300', '100', '200'])
        self.assertEqual([r['cursor_possibly_incomplete'] for r in result['tail_rows']], [False, False, True])
        self.assertFalse(result['all_zero_ring'])

    def test_all_zero_input_is_bytes_not_lifetime_claim(self):
        result = parse_ring(bytes(RING_BYTES), 0, RECORDS)
        self.assertTrue(result['all_zero_ring'])
        self.assertEqual(result['all_zero_slots'], RECORDS)
        self.assertEqual(result['event_counts_nonzero_physical_slots'], {})
        self.assertEqual(len(result['tail_rows']), RECORDS)
        self.assertTrue(all(r['all_zero_bytes'] for r in result['tail_rows']))
        self.assertEqual(result['tail_rows'][-1]['slot'], 0)

    def test_size_rejects_both_truncation_and_extra_bytes(self):
        for size in (0, RING_BYTES - 1, RING_BYTES + 1):
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, 'exactly'):
                parse_ring(bytes(size), 0)

    def test_strict_cursor_and_tail_ranges(self):
        raw = bytes(RING_BYTES)
        for cursor in (-1, 512, True, 1.0, '1'):
            with self.subTest(cursor=cursor), self.assertRaisesRegex(ValueError, 'cursor'):
                parse_ring(raw, cursor)
        for tail in (0, 513, True, 1.0, '1'):
            with self.subTest(tail=tail), self.assertRaisesRegex(ValueError, 'tail'):
                parse_ring(raw, 0, tail)

    def test_nonzero_slot_with_event_zero_counted_without_invented_validity(self):
        raw = bytearray(RING_BYTES)
        raw[2] = 1  # Only padding differs; preserve byte-level ambiguity.
        result = parse_ring(raw, 0, 1)
        self.assertEqual(result['event_counts_nonzero_physical_slots'], {'00000000': 1})
        self.assertFalse(result['tail_rows'][0]['all_zero_bytes'])


if __name__ == '__main__':
    unittest.main()
