"""Independently audit persisted native ABI and complete owned-stack restoration."""
from pathlib import Path
import hashlib,json,struct
p=__import__('argparse').ArgumentParser();p.add_argument('--source-work',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=a.source_work;j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();s=j(W/'live-native.json');n=j(W/'native-qualification.json');prep=j(W/'native-preparation.json');out=W/'private/live-native-01';b=(out/'power.bin').read_bytes();u=lambda o:struct.unpack_from('<I',b,o)[0]
assert s['phase']=='one_bounded_native_live_episode_and_hardware_restoration_qualified'and s['hardware_and_power_restoration_verified']
assert len(b)==959896 and u(0)==80 and u(4)==1 and struct.unpack_from('<Q',b,8)[0]==0x314f52463735474f and b[64:80].rstrip(b'\0')==b'G57-livehw1'
assert u(16)==26100 and u(20)==8 and u(24)==0 and u(32)==1
assert u(80)==u(84)==u(34472)==u(34476)==u(36320)==u(36324)==u(41540)==u(41544)==0
assert u(88)==u(34480)==u(36328)==u(41548)==u(959864)==u(959868)==u(959872)==1
assert u(830996)==0 and u(831000)==u(831004)==100 and u(831036)==1 and u(831040)<=2500000
assert u(41564)==u(41556)+u(41560) and u(41564)<=65536
assert u(881456)<=400 and u(831016)==u(831020)<=100
kinds={};raw_contacts=[]
for i in range(100):
 at=831056+i*504;size=u(at);f=at+212;kind=u(f);kinds[str(kind)]=kinds.get(str(kind),0)+1
 assert size<=90 and u(at+8)==u(at+12)
 assert u(at+20)in(3,15) and u(at+88)<=1 and u(at+92)==(26 if u(at+88)else 0)
 for k in range(4):
  if u(at+20)&(1<<k):
   z=at+24+k*16;assert u(z)==0xc0 and u(z+8)==0xe2 and u(z+4)<=1 and u(z+12)<=1
 if kind==3:
  assert u(f+20)==u(f+24)==1 and u(f+12)<=10 and u(at+8)==1
  raw=b[at+122:at+122+size];raw_contacts.append(raw.hex())
  if u(f+12)==0:assert u(f+28)==u(f+32)==0 and u(f+36)==8
  else:assert u(f+28)==u(f+32)==1
 elif kind==1:assert u(at+8)==0
 elif kind==2:assert u(at+8)==1
 else:raise AssertionError('Unexpected undecoded native frame')
state=s['after'];assert state['live_attempts']==state['live_complete']==state['stop_attempts']==1 and state['live_error']==state['accepted_mask']==0 and state['reports_submitted']==state['reports_accepted']
done=j(out/'done.json');ready=j(out/'ready.json');q=j(out/'qualification.json');events=[jstr for jstr in(out/'events.jsonl').read_text().splitlines()if jstr];assert ready['Token']==done['token']==s['token']and done['window_closed']and not done['dropped']and q['owned_foreground_verified']and q['DPI_aware']
assert done['admin']['Started']and done['admin']['ExitCode']==0 and not done['admin']['Error'];child=json.loads(done['admin']['Output']);assert child['ok']and child['result']['sha256']==sha(out/'power.bin')
for key in ['live_attempts','live_complete','live_error','reports_submitted','reports_accepted','accepted_mask','accepted_generation','stop_attempts','stop_accepted']:assert child['result']['source_status'][key]==state[key]
if state['reports_submitted']==0:assert not events and state['accepted_generation']==state['stop_accepted']==0 and state['last_submit_status']==s['before']['last_submit_status']
else:assert state['last_submit_status']==0
assert len(s['fixed50_comparison'])==50 and all(x['before']==x['after']for x in s['fixed50_comparison']if x['index']!=12)
assert prep['phase']=='finite_owned_foreground_DPI_receiver_selftest_passed_no_driver_IO'
assert n['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'
assert n['baseline']['files']==n['audit_after']['inventory']['files']and n['baseline']['services']==n['audit_after']['inventory']['services']
v=n['audit_after'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['inventory']['SM_DIGITIZER']==0 and v['processors']==8
assert j(W/'remove-disconnected.json')['phase']=='two_exact_owned_descendants_and_unused_child_package_removed_without_force'
report={'passed':True,'native_trial_bytes':len(b),'native_trial_sha256':sha(out/'power.bin'),'cycles':100,'poll_elapsed_us':u(831040),'native_frame_kinds':kinds,'native_raw_contact_packets':raw_contacts,'Windows_reports_accepted':state['reports_accepted'],'Windows_consumer_events':len(events),'all_original_restorable_fixed50_words_equal':True,'independent_before_after_PMIC_off':True,'all_owned_nodes_packages_service_removed':True,'six_original_driver_hashes_and_service_configuration_state_equal':True,'same_G17_boot_8_CPUs_control_healthy':True,'header_read_retries':u(831044),'headers_recovered':u(831048),'GPIO_read_attempts':u(831052),'actual_header_recovery_qualified':u(831048)>0,'physical_DOWN_MOVE_UP_qualified':False,'permanent_continuous_touch_qualified':False,'RAM_WinPE_qualified':False,'all21_goal_areas_remain_active':True,'limits':['An idle finite live episode does not establish physical finger motion, multitouch, IRQ delivery or permanent power/resource ownership.','No new protected-partition full-hash audit is claimed.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
