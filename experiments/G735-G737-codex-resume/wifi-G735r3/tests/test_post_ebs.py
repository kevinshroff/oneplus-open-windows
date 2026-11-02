"""Synthetic register-capture tests; does not create an actual G738 proof."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('post_ebs',ROOT/'post_ebs.py')
p = importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

def prepared_fixture():
    # Actual initial Boot131 inventory; final Prepared state is synthetic test data.
    r = json.loads((ROOT/'evidence/predecessor-boot131-owsi.json').read_text())
    r.update(Version=3,Bytes=1584,Stage=7,Code=0,Prepared=1,Writes=31,AttemptedWrites=31,
             RetainUntilReset=1,PreflightVerified=1,Revalidations=33)
    fields = p.BANK_FIELDS
    raw = [[0x3bbde302,3,0x10066,0xfe8a8cca,0xa64f6358,0xf38ee381,0xb27cf5d3,0x3b397317,0xfbfdefed,0xdebd71c4,0x1dafdd9f,0,0,0],
           [0x3bdfe118,3,0x4002c076,0x42eeccab,0x62daf3ab,0xb627bb6c,0xdfa366fa,0x7f851ebd,0xddbddf3c,0xf2b9fb3b,0xc08db538,0,0,0]]
    for k,s in enumerate(r['Stream']):
        cb=slot=9+k;sid=[0x1401,0x1400][k]
        s.update(Cb=cb,Slot=slot,Sid=sid,CbAddress=p.BASE+0x80000+cb*0x1000,
                 SmrAddress=p.BASE+0x800+slot*4,S2crAddress=p.BASE+0xc00+slot*4,
                 CbarAddress=p.BASE+0x1000+cb*4,Cba2rAddress=p.BASE+0x1800+cb*4,
                 Smr=0x80000000|sid,S2cr=cb,Sctlr=0xe0,Cbar=0x1f000,Cba2r=1,
                 BeforeValid=1,AfterValid=1,SmrReadValid=1,S2crReadValid=1,
                 Before=dict(zip(fields,raw[k])),After=p.INTENDED.copy())
    return r

def snapshot(plan,omit=None,change=None):
    lines = [plan['begin_marker']]
    for r in plan['expected_records']:
        if r['address']==omit:
            continue
        v=r['expected'] ^ (1 if r['address']==change else 0)
        lines.append(f"#{int(r['address'],16):08x} {v:08x}")
    return '\n'.join(lines+[plan['end_marker']])+'\n'

class PostEbsTests(unittest.TestCase):
    def setUp(self):
        self.r=prepared_fixture()
        self.plan=p.make_plan(self.r,'1'*64,p.IMAGE_SHA,132,'root_session_132','a'*24)
    def test_bounded_plan_and_complete_capture(self):
        self.assertEqual(len(self.plan['expected_records']),40)
        self.assertEqual(self.plan['read_bytes'],160)
        for command in self.plan['commands'][1:-1]:
            self.assertRegex(command,r'^!dd \[uc\] -m [0-9a-f]+ L[1-8]$')
        proof=p.compare(self.r,'1'*64,self.plan,snapshot(self.plan))
        self.assertEqual(proof['result'],'pass')
        self.assertEqual(proof['measured_words'],40)
        self.assertFalse(proof['context_verified_by_helper'])
        self.assertTrue(all(x['comparison']=='match' for x in proof['comparisons']))
    def test_every_missing_word_including_zero_fails(self):
        for record in self.plan['expected_records']:
            with self.subTest(record=record['field']):
                proof=p.compare(self.r,'1'*64,self.plan,snapshot(self.plan,omit=record['address']))
                self.assertEqual(proof['result'],'fail')
                missing=[x for x in proof['comparisons'] if x['comparison']=='missing']
                self.assertEqual(len(missing),1)
                self.assertIsNone(missing[0]['actual'])
    def test_every_changed_word_fails_with_measured_detail(self):
        for record in self.plan['expected_records']:
            with self.subTest(record=record['field']):
                proof=p.compare(self.r,'1'*64,self.plan,snapshot(self.plan,change=record['address']))
                self.assertEqual(proof['result'],'fail')
                changed=[x for x in proof['comparisons'] if x['comparison']=='mismatch']
                self.assertEqual(changed[0]['field'],record['field'])
    def test_unreadable_duplicate_unplanned_and_wrong_markers_fail(self):
        text=snapshot(self.plan)
        first=self.plan['expected_records'][0]
        row=f"#{int(first['address'],16):08x} {first['expected']:08x}"
        for bad in [text.replace(row,row.split()[0]+' ????????'),
                    text.replace(row,row+'\n'+row),
                    text.replace(row,row+'\n#deadbeec 00000000')]:
            self.assertEqual(p.compare(self.r,'1'*64,self.plan,bad)['result'],'fail')
        for bad in ['',text.replace(self.plan['begin_marker'],'old_capture'),text+text]:
            with self.assertRaises(p.Invalid):p.compare(self.r,'1'*64,self.plan,bad)
    def test_unsafe_or_unmeasured_owsi_refused(self):
        mutators=[lambda r:r.update(Prepared=0),lambda r:r.update(Writes=0),
                  lambda r:r['Stream'][0].update(CbAddress=0xdeadbeef),
                  lambda r:r['Stream'][0].update(Sid=0x1402),
                  lambda r:r['Stream'][0].update(Slot=1000),
                  lambda r:r['Stream'][0].update(AfterValid=0),
                  lambda r:r['Stream'][0]['After'].pop('Fsr'),
                  lambda r:r['Stream'][0]['After'].update(Tcr=0x3b397317),
                  lambda r:r['Stream'][0]['Before'].update(Sctlr=0xe0),
                  lambda r:r['BeforeS2cr'].__setitem__(104,9),
                  lambda r:r['BeforeSmr'].__setitem__(104,0x00011400),
                  lambda r:r.update(BeforeSmr=r['BeforeSmr'][:16])]
        for mutate in mutators:
            r=copy.deepcopy(self.r);mutate(r)
            with self.assertRaises(p.Invalid):p.make_plan(r,'1'*64,p.IMAGE_SHA,132,'root_session_132','a'*24)
        with self.assertRaises(p.Invalid):p.make_plan(self.r,'1'*64,'0'*64,132,'root_session_132','a'*24)
    def test_plan_digest_or_addresses_cannot_be_changed(self):
        plan=copy.deepcopy(self.plan);plan['expected_records'][0]['address']='0xdeadbeec'
        with self.assertRaises(p.Invalid):p.compare(self.r,'1'*64,plan,snapshot(self.plan))
        with self.assertRaises(p.Invalid):p.compare(self.r,'2'*64,self.plan,snapshot(self.plan))

if __name__=='__main__':unittest.main()
