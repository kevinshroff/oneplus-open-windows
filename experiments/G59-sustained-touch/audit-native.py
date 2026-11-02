"""Independent raw-offset sustained-window audit plus exact software cleanup."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--run',choices=['idle','physical'],default='idle');p.add_argument('--output',type=Path,required=True);p.add_argument('--evidence',type=Path);a=p.parse_args();W=Path(__file__).resolve().parent;J=lambda p:json.loads(p.read_text());E=a.evidence or W;s=J(E/('live-native-'+a.run+'.json'));n=J(E/('native-qualification-'+a.run+'.json'));out=W/('private/live-native-'+a.run);F=lambda name:E/(a.run+'-'+name)if a.evidence else out/name;b=F('power.bin').read_bytes();U=lambda o:struct.unpack_from('<I',b,o)[0];Q=lambda o:struct.unpack_from('<Q',b,o)[0]
assert len(b)==959896 and U(0)==80 and U(4)==1 and Q(8)==0x314f52463935474f and U(16)==26100 and U(20)==8 and U(24)==0 and U(32)==1
assert s['phase']=='one_native_sustained_window_and_restoration_qualified'and s['hardware_and_power_restoration_verified']and n['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'
assert U(80)==U(84)==U(34472)==U(34476)==U(36320)==U(36324)==U(41540)==U(41544)==0
assert U(88)==U(34480)==U(36328)==U(41548)==U(959864)==U(959868)==U(959872)==1
assert U(830996)==0 and U(831000)==U(831004)==2500 and U(831036)==1 and 0<U(831040)<=45000000
wires=U(881456);trace=U(41564);assert U(41576)==4+wires and wires==U(831008)+U(831016) and wires<=10000
assert U(831020)==U(831028)+U(831032) and U(831024)+U(831020)==2500 and U(831016)==U(831020)
assert U(831044)<=2500 and U(831048)<=U(831044) and U(41556)<=2000000 and U(41560)<=1000000 and trace<=3000000
assert U(41632)==U(41636)==0
indices=range(max(0,wires-400),wires)
for i in indices:
 at=881460+(i%400)*196;kind,address,payload,attempted,transport,start,step,state,steps,txdone,rxdone,cancel,abort=struct.unpack_from('<13I',b,at)
 assert kind in(1,2,3,4)and attempted==transport==1 and start==step==cancel==abort==0 and state==4
 if kind==3:expected=bytes.fromhex('f00001027400');assert address==0x10274 and payload==1 and txdone==6 and rxdone==0
 else:
  assert address==(0x1028e if kind==2 else 0x10274)and payload==(payload if kind==2 else 26)
  if kind==2:assert 8<=payload<=64 and payload%8==0
  expected=bytes([0xf1,address>>24,(address>>16)&255,(address>>8)&255,address&255,255,255,255])+bytes(payload);assert txdone==rxdone==payload+8
 assert b[at+52:at+52+len(expected)]==expected and not any(b[at+52+len(expected):at+124])
rows=[]
for i in range(2400,2500):
 at=831056+(i%100)*504;assert U(at)<=90 and U(at+20)in(3,15)and U(at+88)<=1 and U(at+92)in(0,26)
 rows.append({'cycle':i+1,'kind':U(at+212),'points':U(at+224),'elapsed_us':U(at+16),'header_retry':U(at+88)})
assert [r['elapsed_us']for r in rows]==sorted(r['elapsed_us']for r in rows)
v=n['audit_after'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
assert n['baseline']['files']==v['inventory']['files']and n['baseline']['services']==v['inventory']['services']and n['baseline']['DSDT_sha256']==v['inventory']['DSDT_sha256']
assert J(E/('remove-disconnected-'+a.run+'.json'))['phase']=='two_exact_owned_descendants_and_unused_child_package_removed_without_force'
assert len(s['fixed50_comparison'])==50 and all(r['before']==r['after']for r in s['fixed50_comparison']if r['index']!=12)
for key in ['pmic_before','pmic_after']:
 pm=s[key];assert pm['operation_code']==0 and pm['fixed_registers_unchanged']==1 and pm['pmic_status_raw']==0x43 and pm['configuration']==[8,7,0,0,7,7,0,0]
q=s['session_after'];assert q['state']==3 and q['outcome']==1 and q['starts']==q['hardware_calls']==q['thread_joined']==q['result_ready']==1 and q['stop_reason']==q['stop_seen']==q['stop_requests']==0 and q['poll_cycles']==2500 and q['end_us']>q['begin_us']
state=s['source_after'];assert state['live_complete']==state['live_attempts']==state['stop_attempts']==1 and state['live_error']==state['accepted_mask']==0
if a.run=='idle':assert state['reports_submitted']==state['reports_accepted']==state['accepted_generation']==state['stop_accepted']==0 and not F('events.jsonl').read_bytes()
ready=J(F('ready.json'));done=J(F('done.json'));child=json.loads(done['admin']['Output']);assert child['ok']and child['result']['driver_session']==q and child['result']['sha256']==hashlib.sha256(b).hexdigest()
assert ready['Token']==done['token']==s['token']and ready['TrialMode']=='complete'and ready['Foreground']and ready['DPIAware']and done['window_closed']and not done['dropped']and done['admin']['ExitCode']==0
r={'passed':True,'run':a.run,'native_sustained_idle_qualified':a.run=='idle','native_cycles':2500,'offline_audit_native_operations':0,'poll_elapsed_us':U(831040),'total_worker_us':q['end_us']-q['begin_us'],'cumulative_wire_commands':wires,'owner_trace_events':trace,'trace_retained':min(65536,trace),'wire_retained':min(400,wires),'poll_rows_retained':100,'Windows_input_reports':state['reports_submitted'],'raw_capture_bytes':len(b),'raw_capture_sha256':hashlib.sha256(b).hexdigest(),'all_owned_nodes_packages_service_removed':True,'same_G17_eight_CPUs_and_original_inbox_files_services_DSDT':True,'fixed50_exact':all(r['before']==r['after']for r in s['fixed50_comparison']),'fixed49_and_qualified_TCS_response':True,'independent_before_after_PMIC_off':True,'one_driver_owned_result_and_thread_joined':True,'native_active_contact_cancel_qualified':False,'permanent_touch_qualified':False,'all21_goal_areas_active':True,'retained_poll_rows':rows,'limits':['Only the fixed native2500-cycle window is qualified; neither an indefinite input service nor ACPI hardware ownership is established.','The log rings retain bounded tails; early poll/wire/MMIO records overwritten by design are unavailable in this capture.','Owner MMIO counters exclude the12 additional native read-only quiescence checks per completed cycle.']}
a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items()if k!='retained_poll_rows'}))
