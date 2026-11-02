from pathlib import Path
import copy
import importlib.util
import json
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
def module(name):
 spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
g=module('generate');a=module('analyze')
class Tests(unittest.TestCase):
 def receipt(self):
  # Synthetic syntax/admission fixture only; never staged or represented as actual fresh evidence.
  r={'schema':'wifi-live-vdev2-actual-loaded-original/1','BootId':166,'module_base':'fffff80000100000','nt_base':'fffff80010000000','load_stop_pc':'fffff80010000000','original_driver_sha256':g.SYS,'loaded_boundary_16bytes':g.CODE,'root_nonce':'1'*32}
  for k in ('root_qualifies_exact_loaded_PE','root_owns_module_load_hold_before_DriverEntry','root_qualifies_no_other_breakpoints','root_qualifies_MASM_and_native_ARM64_ba_e4','root_qualifies_G550_G717_local_route'):r[k]=True
  return r
 def test_finite_control_source(self):
  c=g.commands(self.receipt());self.assertEqual(c['arm'].count('ba0 e 4'),1);self.assertNotIn('g;',c['arm'])
  for k,x in c.items():
   self.assertNotIn('$><',x);self.assertNotIn('bp /',x);self.assertNotIn(' t;',x);self.assertNotIn('r pc',x)
  self.assertIn('\\n',c['CLASSIFY_BODY']);self.assertNotIn('\\\\n',c['CLASSIFY_BODY'])
  self.assertNotIn('g;',c['CLASSIFY_BODY']);self.assertEqual(c['CLEAN_COMMAND'].count('bc 0'),1);self.assertNotIn('ba0',c['CLEAN_COMMAND'])
  self.assertIn('nt!DbgBreakPoint',c['TIMEOUT_CLEAR_INTERRUPT']);self.assertIn('0x68f1bb22',c['TIMEOUT_CLEAR_INTERRUPT']);self.assertEqual(c['TIMEOUT_CLEAR_INTERRUPT'].count('bc 0'),1)
  r=self.receipt();r['loaded_boundary_16bytes']='00'*16
  with self.assertRaises(ValueError):g.commands(r)
 def test_templates_do_not_invent_entry_or_grants(self):
  for phase in g.PHASES:
   proof,ledger=g.template(phase)
   self.assertFalse(proof['root_selected_live_phase_observation']);self.assertFalse(proof['root_authorizes_source_owned_runtime_CM_resource_qualification'])
   self.assertNotIn('root_qualifies_current_endpoint_BAR0_resource',proof)
   self.assertNotIn('root_qualifies_current_HIF_BAR_virtual_to_physical_binding',proof)
   self.assertIsNone(ledger['native_init_calls_started']);self.assertIsNone(ledger['explicit_scan_calls']);self.assertEqual(ledger['native_call_count_knowledge'],'NOT_OBSERVED_AT_STOP');self.assertFalse(ledger['native_initialization_in_progress'])
 def test_syntax_preview_cannot_execute(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'syntax';g.syntax_preview(out);s=(out/'Observer-SYNTAX-ONLY.ps1').read_text()
   self.assertIn("if($ExecuteReviewedObserver){throw 'SYNTAX PREVIEW IS NOT A RUNTIME WORKFLOW'}",s);self.assertNotIn('__BOOT__',s)
   self.assertTrue(g.strict_load(out/'MANIFEST.json')['not_a_runtime_packet'])
 def test_synthetic_tuple_raw_read_consistency(self):
  # Parser model only. These are invented values, not a captured device tuple.
  values=[0x11112222,0x33334444,0x01020304,0x55556666]
  records=[{'phase':'unforced_fault_read','label':label,'hresult':'00000000','actual_bytes':4,'raw_hex':value.to_bytes(4,'little').hex()} for label,value in zip(('BHI_ERRCODE','BHI_ERRDBG1','BHI_ERRDBG2','BHI_ERRDBG3'),values)]
  records.append({'phase':'complete_held','status_EE_stable':True,'MHI_status_raw':513,'MHI_status_after':513,'EE_raw':2,'EE_after':2,'BHI_error_code_raw':values[0],'BHI_error_debug_raw':values[1:]})
  self.assertEqual(a.actual_tuple(records),values)
  records[1]['actual_bytes']=0
  with self.assertRaises(ValueError):a.actual_tuple(records)
 def test_stop_bounds_do_not_claim_neutrality(self):
  r={'schema':'wifi-live-vdev2-local-result/1','events':[{'previous_go_lower_bound_ms':10,'first_observed_ms':20,'stop_duration_upper_bound_ms':100,'resumed':True,'within_selected_budget':True}], 'failure':None,'cleanup_failure':None,'resumed':True,'owned_slot_removed':True,'selected_capture_completed':True}
  x=a.pause_result(r);self.assertEqual(x['classification'],'WITHIN_CHOSEN_PAUSE_BUDGET');self.assertFalse(x['unperturbed_proved'])
  r['events'][0]['within_selected_budget']=False;self.assertEqual(a.pause_result(r)['classification'],'PAUSE_PERTURBED_BUDGET_EXCEEDED')
  r['events'][0]['previous_go_lower_bound_ms']=None;self.assertEqual(a.pause_result(r)['classification'],'PAUSE_UNMEASURED_OR_INCONSISTENT')
 def test_CE_decisions_require_hardware_for_empty_ring(self):
  ce={'after':{'destination':{'actual_RAM_shadow':12,'local_dword_index':42},'status':{'actual_RAM_shadow':44,'local_dword_index':44}},'hardware':None,'shadow_change_observed':False}
  self.assertTrue(a.ce_decision(ce).startswith('EMPTY_RAM_WITHOUT_HARDWARE'))
  ce['hardware']={'qualified':True,'destination_HP':42,'destination_TP':12,'status_HP':44,'status_TP':44};self.assertTrue(a.ce_decision(ce).startswith('EMPTY_STATUS_WITH_VISIBLE'))
  ce['hardware']['status_HP']=48;self.assertTrue(a.ce_decision(ce).startswith('HARDWARE_HAS_UNREAPED'))
if __name__=='__main__':unittest.main()
