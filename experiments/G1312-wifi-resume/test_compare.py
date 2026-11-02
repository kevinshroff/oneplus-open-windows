"""Synthetic artifact tests, never target operations."""
import json
from pathlib import Path
import tempfile
import unittest
import compare
import templates


class PairTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pre = self.root / 'pre.jsonl'
        self.post = self.root / 'post.jsonl'
        self.ledger = self.root / 'ledger.json'
        self.marker = self.root / 'marker.json'
        self.identity = dict(boot_id=162, phone_session='1' * 32, image_sha256='2' * 64)
        self.make_pair()

    def rows(self, phase, values, refused=False):
        identity = dict(self.identity, root_nonce=('3' if phase == 'PRE_HOST_INIT' else '4') * 32,
                        action_ledger_sha256='5' * 64, observation_phase=phase)
        rows = [dict(identity, phase='begin'), dict(identity, phase='phase_consumed_before_debugger_connect')]
        if refused:
            return rows + [dict(identity, phase='refused_or_failed')]
        for label, value in zip(('BHI_ERRCODE', 'BHI_ERRDBG1', 'BHI_ERRDBG2', 'BHI_ERRDBG3'), values):
            rows.append(dict(identity, phase='unforced_fault_read', label=label,
                             hresult='00000000', actual_bytes=4, raw_hex=value.to_bytes(4, 'little').hex()))
        rows.append(dict(identity, phase='complete_held', status_EE_stable=True,
                         MHI_status_raw=0x201, MHI_status_after=0x201, EE_raw=2, EE_after=2,
                         BHI_error_code_raw=values[0], BHI_error_debug_raw=values[1:]))
        return rows

    def write_rows(self, path, rows):
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))

    def make_pair(self, refused=False, changed=False):
        values = [0xcafecace, 0xcafecace, 0x014feeab, 496]
        self.write_rows(self.pre, self.rows('PRE_HOST_INIT', [0, 0, 0, 0] if changed else values, refused))
        marker = dict(self.identity, schema='G1295-host-phase-once/1', phase='PRE_HOST_INIT',
                      root_nonce='3' * 32, action_ledger_sha256='5' * 64)
        self.marker.write_text(json.dumps(marker))
        ledger = dict(self.identity, schema='G1295-actual-boot-action-ledger/1', phase='POST_STALL',
                      pre_phase_result_sha256=compare.digest(self.pre), pre_phase_marker_sha256=compare.digest(self.marker))
        self.ledger.write_text(json.dumps(ledger))
        rows = self.rows('POST_STALL', values)
        for row in rows:
            row['action_ledger_sha256'] = compare.digest(self.ledger)
        self.write_rows(self.post, rows)

    def run_pair(self):
        return compare.compare(self.pre, self.post, self.ledger, self.marker)

    def test_same(self):
        self.assertTrue(self.run_pair()['decision'].startswith('SAME_OBSERVED_TUPLE'))

    def test_changed(self):
        self.make_pair(changed=True)
        self.assertTrue(self.run_pair()['decision'].startswith('CHANGED_OBSERVED_TUPLE'))

    def test_refused_pre_is_not_zero(self):
        self.make_pair(refused=True)
        self.assertIsNone(self.run_pair()['pre_tuple_hex'])

    def test_tampered_pre(self):
        self.pre.write_text(self.pre.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'PRE result not bound'):
            self.run_pair()

    def test_wrong_image(self):
        rows = [json.loads(line) for line in self.post.read_text().splitlines()]
        for row in rows:
            row['image_sha256'] = '9' * 64
        self.write_rows(self.post, rows)
        with self.assertRaisesRegex(ValueError, 'image mismatch'):
            self.run_pair()

    def test_partial_or_unstable(self):
        rows = [json.loads(line) for line in self.post.read_text().splitlines()]
        self.write_rows(self.post, rows[:-1])
        with self.assertRaisesRegex(ValueError, 'outcome'):
            self.run_pair()
        rows[-1]['status_EE_stable'] = False
        self.write_rows(self.post, rows)
        with self.assertRaisesRegex(ValueError, 'state/EE changed'):
            self.run_pair()

    def test_templates_inert(self):
        values = dict(templates.templates())
        self.assertEqual(len(values), 4)
        for name, value in values.items():
            self.assertIsNone(value['boot_id'])
            if 'ledger' in name:
                self.assertIsNone(value['native_init_calls'])
            else:
                self.assertFalse(value['root_owns_break6'])
                if value['phase'] == 'PRE_HOST_INIT':
                    self.assertNotIn('failed_scan_log', value['actual_evidence_sha256'])


if __name__ == '__main__':
    unittest.main()
