"""Synthetic success derived from actual Boot132 inventory, never hardware proof."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('post',ROOT/'post_ebs.py')
post=importlib.util.module_from_spec(spec);spec.loader.exec_module(post)

def fixture():
    r=json.loads((ROOT.parents[2]/'work/handover-resume-G737/G735r3-ACTUAL-OWSI.json').read_text())
    r.update(Version=4,Stage=7,Code=0,Prepared=1,Writes=31,AttemptedWrites=31,Revalidations=33)
    for s in r['Stream']:
        s.update(Smr=0x80000000|s['Sid'],S2cr=s['Cb'],Sctlr=0xe0,Cbar=0x1f000,Cba2r=1)
        s['After']=dict(post.INTENDED)
    return r

class PostTests(unittest.TestCase):
    def test_exactzero_and_version(self):
        r=fixture();records=post.expected_records(r)
        self.assertEqual(len(records),40)
        self.assertEqual([x['expected'] for x in records if x['field'].endswith('.Tcr2')],[0,0])
        r['Version']=3
        with self.assertRaises(post.Invalid):post.expected_records(r)
    def test_readback60_is_never_accepted(self):
        r=fixture();p=post.make_plan(r,'a'*64,post.IMAGE_SHA,133,'synthetic_session','ab'*8)
        text='\n'.join([p['begin_marker']]+[x['address'][2:]+' '+format(x['expected'],'08x') for x in p['expected_records']]+[p['end_marker']])
        self.assertEqual(post.compare(r,'a'*64,p,text)['result'],'pass')
        tcr=next(x for x in p['expected_records'] if x['field'].endswith('.Tcr2'))
        text=text.replace(tcr['address'][2:]+' 00000000',tcr['address'][2:]+' 00000060')
        self.assertEqual(post.compare(r,'a'*64,p,text)['result'],'fail')

if __name__=='__main__':unittest.main()
