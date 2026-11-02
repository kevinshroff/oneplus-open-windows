"""Offline only: new exclusive inert host-local workflow; never connects debugger."""
from pathlib import Path
import argparse
import hashlib
import json
import re

HERE=Path(__file__).resolve().parent
SYS='802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56'
CODE='7f2303d5f353bda9f55b01a9f76302a9'
RVA=0x1ea630
PHASES=('ARM_LIVE_VDEV2','PRE_LIVE_VDEV2','POST_STALL')
COMMON=('context','current_tables','loaded_owner','loaded_original_driver','accepted_boot_receipt','normal_boot_admission','native_init_selection','boundary_source')

def need(ok,why):
 if not ok:raise ValueError(why)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n')
def strict_load(path):
 def unique(rows):
  d={}
  for k,v in rows:
   need(k not in d,'Duplicate JSON field');d[k]=v
  return d
 return json.loads(path.read_text(),object_pairs_hook=unique)
def evidence_keys(phase):
 extra={'ARM_LIVE_VDEV2':('owned_load_stop',),'PRE_LIVE_VDEV2':('source_resource_origin_contract','arm_marker','owned_boundary_stop'),'POST_STALL':('source_resource_origin_contract','native_init_outcome','failed_scan_log','pre_phase_result','pre_phase_marker','arm_marker')}[phase]
 return list(COMMON+extra)
def template(phase):
 keys=evidence_keys(phase)
 ledger={'schema':'wifi-live-vdev2-action-ledger/1','phase':phase,'boot_id':None,'phone_session':None,'image_sha256':None,'created_utc':None,
 'native_call_count_knowledge':'NOT_OBSERVED_AT_STOP','explicit_scan_count_knowledge':'NOT_OBSERVED_AT_STOP','native_init_calls_started':None,'explicit_scan_calls':None,'root_force_calls':None,'root_native_diagnostic_calls':None,'root_reset_calls':None,'root_status_clear_calls':None,'root_window_write_calls':None,
 'native_initialization_in_progress':False,'actual_single_init_outcome_recorded':False,'actual_post_init_failure_boundary_recorded':False,
 'root_proves_original_driver_no_unload_in_selected_interval':False,'root_proves_gpu_owner_broker_absent_stopped4':False,'actual_evidence_sha256':{k:None for k in keys}}
 proof={'schema':'wifi-live-vdev2-observation/1','phase':phase,'boot_id':None,'phone_session':None,'image_sha256':None,'created_utc':None,'root_nonce':None,
 'root_selected_live_phase_observation':False,'original_driver_base':None,'original_driver_sha256':SYS,'root_owns_live_vdev2_boundary_stop':False,
 'root_owns_module_load_hold_before_DriverEntry':False,'root_selects_naturally_selected_CE2_hardware_reads':False,
 'action_ledger_file':None,'root_qualifies_actual_fresh_normal_boot':False,'root_authorizes_source_owned_runtime_CM_resource_qualification':False,'expected_fixed_BAR0_base':None,'maximum_reviewed_BAR0_bytes':0,
 'root_attests_no_root_selected_force_native_diagnostic_reset_or_error_clear_in_selected_interval':False,
 'nt_base':None,'held_pc':None,'owner_base':None,'owner_size':None,'owner_timestamp':None,'owner_checksum':None,'root_owns_break6':False,
 'root_qualifies_current_tables_and_resource_owner':False,'root_qualifies_fixed_physical_device_ranges_uncached':False,'actual_evidence_sha256':{k:None for k in keys+['action_ledger']}}
 return proof,ledger

def qualified_receipt(r):
 need(r.get('schema')=='wifi-live-vdev2-actual-loaded-original/1','Actual loaded-original schema required')
 need(type(r.get('BootId')) is int and r['BootId']>165,'Fresh BootId above consumed165 required')
 need(re.fullmatch('[0-9a-f]{16}',r.get('module_base','')) is not None,'Actual base format')
 q=int(r['module_base'],16);need(0xffff000000000000<=q<0xffffffffffff0000 and q&0xfff==0,'Aligned actual loaded base')
 need(r.get('original_driver_sha256')==SYS and r.get('loaded_boundary_16bytes')==CODE,'Actual original code/identity mismatch')
 for k in ('root_qualifies_exact_loaded_PE','root_owns_module_load_hold_before_DriverEntry','root_qualifies_no_other_breakpoints','root_qualifies_MASM_and_native_ARM64_ba_e4','root_qualifies_G550_G717_local_route'):
  need(r.get(k) is True,'Missing actual root receipt observation: '+k)
 need(re.fullmatch('[0-9a-f]{16}',r.get('load_stop_pc','')) is not None and int(r['load_stop_pc'],16)>=0xffff000000000000,'Actual load stop PC')
 need(re.fullmatch('[0-9a-f]{32}',r.get('root_nonce','')) is not None,'Actual nonce')
 need(re.fullmatch('[0-9a-f]{16}',r.get('nt_base','')) is not None and int(r['nt_base'],16)>=0xffff000000000000 and int(r['nt_base'],16)&0xfff==0,'Actual current kernel base')
 return q

def commands(r):
 q=qualified_receipt(r);pc=q+RVA;tag='WIFILIVE_'+r['root_nonce'];base=f'0x{q:016x}';entry=f'0x{pc:016x}'
 # All dereferences in classification are ordinary bounded source argument RAM. No target write.
 guard=f'(dwo(0xfffff780000002c4)==0x{r["BootId"]:x}) and (@pc=={entry}) and (@$eventip=={entry}) and (@$bp0=={entry}) and (dwo({entry})==0xd503237f)'
 pointer='((@x1 & 0xffff000000000000)==0xffff000000000000) and ((@x2 & 0xffff000000000000)==0xffff000000000000) and (@x1<=0xffffffffffffeffb) and (@x2<=0xffffffffffff5557)'
 own=f'({guard}) and ({pointer})'
 classifier=f'.echo HITBEGIN; .if ({own}) {{ .echo WIFILIVE_HIT; r pc; .echo WIFILIVE_REQUEST; dd @x1 L1; .echo WIFILIVE_VDEV; db @x2+0x9aa8 L1; .echo WIFILIVE_VALUES_END; }} .else {{ .echo WIFILIVE_REFUSED_HIT; }}; .echo HITEND'
 initialbegin=tag+'_INITIAL_BEGIN';initialend=tag+'_INITIAL_END'
 initialguard=f'(dwo(0xfffff780000002c4)==0x{r["BootId"]:x}) and (@pc==0x{r["load_stop_pc"]}) and (@$bp0=={entry}) and (dwo({entry})==0xd503237f) and (dwo({entry}+4)==0xa9bd53f3) and (dwo({entry}+8)==0xa9015bf5) and (dwo({entry}+0xc)==0xa90263f7)'
 initial=f'.echo {initialbegin}; .if ({initialguard}) {{ .echo WIFILIVE_INITIAL_ACCEPT; }} .else {{ .echo WIFILIVE_INITIAL_REFUSED; }}; .echo {initialend}'
 skipbegin=tag+'_SKIP0_BEGIN';skipend=tag+'_SKIP0_END'
 skip=f'.echo {skipbegin}; .if (({own}) and (dwo(@x1)==0x109) and (by(@x2+0x9aa8)==0)) {{ .echo WIFILIVE_SKIP0_RESUME; .echo {skipend}; g; }} .else {{ .echo WIFILIVE_SKIP_REFUSED; .echo {skipend}; }}'
 cleanbegin=tag+'_CLEAN_BEGIN';cleanend=tag+'_CLEAN_END'
 # External cleanup operation, never a breakpoint command/callback; no rearm or PC edit.
 clean=f'.echo {cleanbegin}; .if ({guard}) {{ bc 0; .echo WIFILIVE_OWNED_SLOT_REMOVED; .echo WIFILIVE_SELECTED_RESUME; .echo {cleanend}; g; }} .else {{ .echo WIFILIVE_CLEAN_REFUSED; .echo {cleanend}; }}'
 arm=f'ba0 e 4 {entry}; bl 0; .bpcmds'

 timeoutbegin=tag+'_TIMEOUT_CLASSIFY_BEGIN';timeoutend=tag+'_TIMEOUT_CLASSIFY_END'
 sourceguard=f'(dwo(0xfffff780000002c4)==0x{r["BootId"]:x}) and (@$bp0=={entry}) and (wo({base})==0x5a4d) and (dwo({base}+0x3c)==0x108) and (dwo({base}+0x108)==0x4550) and (wo({base}+0x10c)==0xaa64) and (dwo({base}+0x110)==0x68f1bb22) and (dwo({base}+0x158)==0x443000) and (dwo({base}+0x160)==0x3b746d) and (dwo({entry})==0xd503237f) and (nt!DebugService2==(0x{r["nt_base"]}+0x201400))'
 hardware=f'({sourceguard}) and (@pc=={entry}) and (@$eventip=={entry})'
 interrupt=f'({sourceguard}) and (@pc==nt!DbgBreakPoint) and (@$eventip==@pc) and (dwo(nt!DbgBreakPoint)==0xd43e0000)'
 timeoutclass=f'.echo {timeoutbegin}; .lastevent; .if ({hardware}) {{ .echo WIFILIVE_TIMEOUT_OWN_HARDWARE; }}; .if ({interrupt}) {{ .echo WIFILIVE_TIMEOUT_INTERRUPT_PC; }}; .echo {timeoutend}'
 clearbegin=tag+'_TIMEOUT_CLEAR_BEGIN';clearend=tag+'_TIMEOUT_CLEAR_END'
 def clear(condition):return f'.echo {clearbegin}; .if ({condition}) {{ bc 0; .echo WIFILIVE_TIMEOUT_OWNED_SLOT_REMOVED; .echo {clearend}; g; }} .else {{ .echo WIFILIVE_TIMEOUT_CLEAR_REFUSED; .echo {clearend}; }}'
 timeoutvalues={'TIMEOUT_CLASSIFY':timeoutclass,'TIMEOUT_CLASSIFY_BEGIN':timeoutbegin,'TIMEOUT_CLASSIFY_END':timeoutend,'TIMEOUT_CLEAR_BEGIN':clearbegin,'TIMEOUT_CLEAR_END':clearend,'TIMEOUT_CLEAR_HARDWARE':clear(hardware),'TIMEOUT_CLEAR_INTERRUPT':clear(interrupt)}

 values=dict(timeoutvalues,**{'PREFIX':tag,'BASE':r['module_base'],'PC':f'{pc:016x}','BOOT':str(r['BootId']),'INITIAL_COMMAND':initial,'INITIAL_BEGIN':initialbegin,'INITIAL_END':initialend,'CLASSIFY_BODY':classifier,'SKIP_COMMAND':skip,'SKIP_BEGIN':skipbegin,'SKIP_END':skipend,'CLEAN_COMMAND':clean,'CLEAN_BEGIN':cleanbegin,'CLEAN_END':cleanend,'arm':arm})
 for key,value in values.items():
  need(chr(34) not in value,'Embedded double quote is unsafe for legacy PowerShell native argv: '+key)
 return values

def generate(receipt,receipt_sha,out):
 need(digest(receipt)==receipt_sha,'Actual receipt hash mismatch')
 r=strict_load(receipt);values=commands(r);need(not out.exists(),'New exclusive output required')
 exe=HERE/'LiveVdev2Observer-amd64.exe';need(exe.is_file(),'Fresh crossbuild required')
 values.update(RECEIPT_SHA=receipt_sha,READER_SHA=digest(exe))
 text=(HERE/'Observer.ps1.in').read_text()
 for k,v in values.items():
  if k!='arm':text=text.replace('__'+k+'__',v)
 need('__' not in text,'Unbound source placeholder')
 out.mkdir(parents=True)
 (out/'Observer.ps1').write_text(text)
 cleanup=(HERE/'Cleanup-Timeout.ps1.in').read_text()
 for k,v in values.items():
  if k!='arm':cleanup=cleanup.replace('__'+k+'__',v)
 need('__' not in cleanup,'Unbound cleanup source')
 (out/'Cleanup-Timeout.ps1').write_text(cleanup)
 (out/'LiveVdev2Observer-amd64.exe').write_bytes(exe.read_bytes())
 (out/'Register-Observer.ps1').write_bytes((HERE/'Register-Observer.ps1').read_bytes())
 (out/'ARM-MANUAL-ONLY.txt').write_text('# Consume actual ARM intent before this independently reviewed command. No auto-go.\n'+values['arm']+'\n')
 for phase in PHASES:
  proof,ledger=template(phase);write(out/(phase+'-proof.json'),proof);write(out/(phase+'-ledger.json'),ledger)
 review={'schema':'wifi-live-vdev2-local-observer/1','accepted_local_observer_operation':False,'BootId':r['BootId'],'module_base':r['module_base'],'loaded_receipt_sha256':receipt_sha,
  'observer_source_sha256':digest(out/'Observer.ps1'),'phone_session':None,'image_sha256':None,'kd_pid':None,'kd_run_token':None,'actual_debugger_log':None,
  'root_confirms_original_one_init_one_scan_task_only':False,'root_owns_pending_initial_module_load_hold':False,'root_confirms_no_competing_debugger_actor':False,
  'arm_marker_sha256':None,'pre_proof_template_sha256':None,'pre_ledger_template_sha256':None,'max_owned_hits':2,'poll_interval_ms':25,'wait_seconds':15,'max_stop_upper_bound_ms':250}
 write(out/'observer-review.json',review)
 write(out/'cleanup-review.json',{'schema':'wifi-live-vdev2-timeout-cleanup/1','accepted_cleanup':False,'BootId':r['BootId'],'module_base':r['module_base'],'loaded_receipt_sha256':receipt_sha,'root_confirms_observer_terminal_timeout':False,'root_owns_exact_armed_slot0_from_same_arm_marker':False,'root_confirms_no_competing_debugger_actor':False,'cleanup_source_sha256':digest(out/'Cleanup-Timeout.ps1'),'observer_result_sha256':None,'arm_marker_sha256':None,'kd_pid':None,'kd_run_token':None,'actual_debugger_log':None})
 write(out/'MANIFEST.json',{'schema':'wifi-live-vdev2-inert-package/1','observer_source_version':2,'BootId':r['BootId'],'loaded_receipt_sha256':receipt_sha,
  'source_files':{p.name:digest(p) for p in out.iterdir() if p.is_file()},'runtime_approvals_all_false':True,'staged_or_executed':False,'native_reader_executed':False,
  'maximum_owned_hits':2,'target_memory_writes':0,'window_writes':0,'callbacks':0,'rearms':0,'steps':0,'interrupt_calls':0,'all_control_is_independent_host_local':True})
 return out/'MANIFEST.json'

def syntax_preview(out):
 """Neutral parse-only carrier. Explicit execute always rejects, even if settings are edited."""
 need(not out.exists(),'Exclusive syntax-preview output required')
 # These are neutral syntax tokens, NOT a synthetic boot/admission/evidence receipt.
 values={'TIMEOUT_CLASSIFY':'.echo SYNTAX_ONLY','TIMEOUT_CLASSIFY_BEGIN':'SYNTAX_ONLY_BEGIN','TIMEOUT_CLASSIFY_END':'SYNTAX_ONLY_END','TIMEOUT_CLEAR_BEGIN':'SYNTAX_ONLY_BEGIN','TIMEOUT_CLEAR_END':'SYNTAX_ONLY_END','TIMEOUT_CLEAR_HARDWARE':'.echo SYNTAX_ONLY','TIMEOUT_CLEAR_INTERRUPT':'.echo SYNTAX_ONLY','BOOT':'0','BASE':'0000000000000000','PC':'0000000000000000','RECEIPT_SHA':'0'*64,'READER_SHA':'0'*64,'PREFIX':'SYNTAX_PREVIEW',
  'INITIAL_COMMAND':'.echo SYNTAX_ONLY','INITIAL_BEGIN':'SYNTAX_ONLY_BEGIN','INITIAL_END':'SYNTAX_ONLY_END','CLASSIFY_BODY':'.echo SYNTAX_ONLY',
  'SKIP_COMMAND':'.echo SYNTAX_ONLY','SKIP_BEGIN':'SYNTAX_ONLY_BEGIN','SKIP_END':'SYNTAX_ONLY_END','CLEAN_COMMAND':'.echo SYNTAX_ONLY','CLEAN_BEGIN':'SYNTAX_ONLY_BEGIN','CLEAN_END':'SYNTAX_ONLY_END'}
 text=(HERE/'Observer.ps1.in').read_text()
 for k,v in values.items():text=text.replace('__'+k+'__',v)
 text=text.replace("if(!$ExecuteReviewedObserver){", "if($ExecuteReviewedObserver){throw 'SYNTAX PREVIEW IS NOT A RUNTIME WORKFLOW'}\nif(!$ExecuteReviewedObserver){",1)
 need('__' not in text,'Unbound syntax carrier')
 out.mkdir(parents=True);(out/'Observer-SYNTAX-ONLY.ps1').write_text(text)
 cleanup=(HERE/'Cleanup-Timeout.ps1.in').read_text()
 for k,v in values.items():cleanup=cleanup.replace('__'+k+'__',v)
 cleanup=cleanup.replace('if(!$ExecuteReviewedCleanup){',"if($ExecuteReviewedCleanup){throw 'SYNTAX PREVIEW IS NOT A RUNTIME WORKFLOW'}\nif(!$ExecuteReviewedCleanup){",1)
 need('__' not in cleanup,'Unbound cleanup syntax carrier')
 (out/'Cleanup-Timeout-SYNTAX-ONLY.ps1').write_text(cleanup)
 (out/'Register-Observer.ps1').write_bytes((HERE/'Register-Observer.ps1').read_bytes())
 for phase in PHASES:
  proof,ledger=template(phase);write(out/(phase+'-proof.template.json'),proof);write(out/(phase+'-ledger.template.json'),ledger)
 write(out/'MANIFEST.json',{'schema':'wifi-live-vdev2-syntax-preview-only/1','observer_source_version':2,'not_a_runtime_packet':True,'actual_context_supplied':False,'runtime_approvals_all_false':True,
  'files':{p.name:digest(p) for p in out.iterdir() if p.is_file()}})
 return out/'MANIFEST.json'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--receipt',type=Path);p.add_argument('--receipt-sha256');p.add_argument('--syntax-preview',action='store_true');p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if a.syntax_preview:
  need(a.receipt is None and a.receipt_sha256 is None,'Syntax-only mode admits no receipt');print(syntax_preview(a.out))
 else:
  need(a.receipt is not None and a.receipt_sha256 is not None,'Actual receipt/hash required');print(generate(a.receipt,a.receipt_sha256,a.out))
if __name__=='__main__':main()
