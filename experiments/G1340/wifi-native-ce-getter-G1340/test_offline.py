import unittest,pathlib,struct
import patch,verify_candidate
class Offline(unittest.TestCase):
 def test_actual_and_corruption(self):
  if not BASE or not CANDIDATE:self.skipTest('Pass explicit privately obtained base/candidate')
  b=pathlib.Path(BASE).read_bytes();c=pathlib.Path(CANDIDATE).read_bytes();self.assertTrue(verify_candidate.verify(b,c)['unchanged_outside_body'])
  for at in [0,1365148,1365428]:
   bad=bytearray(c);bad[at]^=1
   with self.assertRaises(ValueError):verify_candidate.verify(b,bytes(bad))
 def test_flow_relocations(self):
  if not CANDIDATE:self.skipTest('Pass actual candidate')
  c=pathlib.Path(CANDIDATE).read_bytes();b=c[1365148:1365148+264];f=patch.validate_body(b);self.assertEqual(f['BL_targets'],['0x1eb588'])
  bad=bytearray(b);struct.pack_into('<I',bad,0,0x94000000) # unexpected additional BL
  with self.assertRaises(ValueError):patch.validate_body(bytes(bad))
 def test_client_has_no_implicit_calls(self):
  d=pathlib.Path(__file__).parent;cs=(d/'CeGetter.cs').read_text();ps=(d/'Query-Once.ps1').read_text()
  self.assertIn('new uint[]{2,3,0,1}:new uint[]{2}',cs);self.assertIn('if(!accepted)break',cs);self.assertIn('if(!$ExecuteRootReviewedQuery)',ps)
  for bad in ['WlanScan','Get-NetAdapterStatistics','InvokeOnce','ScmApertureOnce =','Start-Service','Restart-Service']:self.assertNotIn(bad,cs+ps)
BASE=CANDIDATE=None
if __name__=='__main__':
 import sys
 if '--base' in sys.argv:i=sys.argv.index('--base');BASE=sys.argv.pop(i+1);sys.argv.pop(i)
 if '--candidate'in sys.argv:i=sys.argv.index('--candidate');CANDIDATE=sys.argv.pop(i+1);sys.argv.pop(i)
 unittest.main()
