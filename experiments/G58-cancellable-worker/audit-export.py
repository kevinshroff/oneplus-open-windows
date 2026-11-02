"""Verify exported raw cancellation, frozen owner state and complete removal."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();E=a.evidence;J=lambda p:json.loads(p.read_text());results={}
for mode,reason in [('stop',1),('close',2)]:
 b=(E/(mode+'-power.bin')).read_bytes();u=lambda o:struct.unpack_from('<I',b,o)[0];assert len(b)==959896 and u(0)==80 and struct.unpack_from('<Q',b,8)[0]==0x314f52463835474f and u(16)==26100 and u(20)==8
 assert u(80)==6 and u(41540)==21 and u(84)==u(34476)==u(36324)==u(41544)==0 and u(88)==u(34480)==u(36328)==u(41548)==u(959864)==u(959868)==u(959872)==1
 assert u(41576)==3 and u(831000)==100 and u(831004)==u(881456)==0
 s=J(E/('cancel-native-'+mode+'.json'));n=J(E/('native-qualification-'+mode+'.json'));q=s['session_after'];assert q['starts']==q['hardware_calls']==q['thread_joined']==q['result_ready']==1 and q['state']==3 and q['outcome']==2 and q['stop_reason']==reason and q['stop_seen']>=1 and q['end_us']>=q['stop_us']>=q['begin_us']
 assert s['hardware_and_power_restoration_verified']and n['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored';assert len(s['fixed50_comparison'])==50 and all(r['before']==r['after']for r in s['fixed50_comparison']if r['index']!=12)
 for key in ['pmic_before','pmic_after']:
  pm=s[key];assert pm['operation_code']==0 and pm['fixed_registers_unchanged']==1 and pm['pmic_status_raw']==0x43 and pm['configuration']==[8,7,0,0,7,7,0,0]
 v=n['audit_after'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
 assert n['baseline']['files']==v['inventory']['files']and n['baseline']['services']==v['inventory']['services']and n['baseline']['DSDT_sha256']==v['inventory']['DSDT_sha256']
 assert J(E/('remove-disconnected-'+mode+'.json'))['phase']=='two_exact_owned_descendants_and_unused_child_package_removed_without_force'
 assert (E/(mode+'-events.jsonl')).read_bytes()==b'';state=s['source_after'];assert state['reports_submitted']==state['reports_accepted']==state['accepted_mask']==state['accepted_generation']==state['stop_accepted']==state['live_complete']==0 and state['live_attempts']==state['stop_attempts']==1 and state['live_error']==6
 ready=J(E/(mode+'-ready.json'));done=J(E/(mode+'-done.json'));child=json.loads(done['admin']['Output']);assert child['ok']and child['result']['driver_session']==q and child['result']['sha256']==hashlib.sha256(b).hexdigest()and child['result']['stop_at_phase']==8
 assert ready['Token']==done['token']==s['token']and ready['TrialMode']==mode and ready['Foreground']and ready['DPIAware']and done['window_closed']and not done['dropped']and done['admin']['ExitCode']==0
 results[mode]={'raw_sha256':hashlib.sha256(b).hexdigest(),'stop_to_worker_finish_us':q['end_us']-q['stop_us'],'zero_input':True,'driver_owned_result_and_thread_join':True,'hardware_and_original_software_restored':True}
r={'passed':True,'sessions':results,'native_power_transition_removal_qualified':False,'continuous_touch_qualified':False,'native_operations':0};a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
