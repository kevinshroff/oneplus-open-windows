"""Offline audit of three real one-finger captures, orientation and full cleanup."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G52';X=R/'experiments/G52-physical-touch';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=j(E/'build.json');proof=j(E/'signature-verification.json');summaries=[];sessions=set()
for label in ['center','upper-left','upper-right']:
 n=j(E/('native-'+label+'.json'));r=n['trial'];t=r['touch'];sp=r['spi'];en=sp['engine'];sessions.add(n['phone_session'])
 assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and n['safe_exit_verified']
 assert r['operation_code']==r['restore_error']==r['RSC_uncertain']==r['observer_uncertain']==0
 assert r['restored']==r['safe_release']==r['fixed_registers_unchanged']==r['on_verified']==r['off_verified']==1
 assert n['driver_sha256']==proof['signed_driver_sha256']and n['client_sha256']==build['Go_client']['output_sha256']
 assert n['intent']['loads']==n['intent']['power_trials']==n['intent']['event_flag_zero_writes_max']==1 and n['intent']['contact_window_requested_ms']==5000
 for row in n['jobs'].values():
  q=row['receipt'];assert q['status']=='ok'and q.get('exit_code',0)==0
  assert q['session']==(n['phone_session']if q['node']=='phone'else'00000000000000000000000000000000')
 assert t['operation_code']==t['restore_error']==0 and t['command_attempted']==4 and t['cancel_sent']==t['abort_sent']==0
 assert t['transport_ok']==t['restored']==t['bus_quiescent']==t['lengths_restored']==1 and t['full_IC_info_checksum_verified']
 assert t['info_length']==242 and t['tx_done']==t['rx_done']==250
 ic=bytes(t['wire_RX'][8:250]);assert len(ic)==242 and sum(ic[:-2])&65535==int.from_bytes(ic[-2:],'little')==6850
 assert ic==(E/'IC-info-242.bin').read_bytes()
 rep=t['report'];ack=t['ack'];post=t['post_report'];
 for f in [rep,ack,post]:assert f['attempted']==f['transport_ok']==f['contract_verified']==1 and f['cancel_sent']==f['abort_sent']==0 and f['state']==4
 assert rep['tx_done']==rep['rx_done']==34 and rep['event_flags']==0x40 and rep['header_checksum_valid']==1
 assert bytes(rep['wire_RX'][8:16])==bytes.fromhex('4001000000034400')
 assert ack['tx_done']==6 and ack['rx_done']==0 and ack['wire_TX']==[0xf0,0,1,2,0x74,0]+[0]*30
 assert post['tx_done']==post['rx_done']==34 and post['header_checksum_valid']==post['body_complete']==post['body_checksum_valid']==1
 assert post['event_flags']==0x80 and post['point_count']==1 and post['point_type']==2
 b=bytes(post['wire_RX'][8:34]);assert b==(E/(label+'-contact26.bin')).read_bytes() and len(b)==26
 assert sum(b[:6])&65535==int.from_bytes(b[6:8],'little')and sum(b[8:16])&65535==int.from_bytes(b[16:18],'little')
 assert b[8]>>4==0 and b[8]&15==2
 d=j(E/(label+'-decoded.json'));assert d['journal_sha256']==sha(E/('native-'+label+'.json'))and d['native_job']==n['jobs']['event-ack-trial']['id']
 assert d['trial_sha256']==hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 assert d['decoder_sha256']==sha(X/'g52_report.c')and d['post_report']['Kind']==3 and d['post_report']['Error']==0
 c=d['post_report']['contacts'][0];assert [c['X'],c['Y']]==[int.from_bytes(b[10:12],'little'),int.from_bytes(b[12:14],'little')]
 cmd=[x['value']for x in t['trace']if x['kind']==2 and x['address']=='0xa90600'];assert cmd==[0x18000000,0x18000000,0x08000000,0x18000000]
 assert t['pins_before']==t['pins_after']and t['lengths_before']==t['lengths_after']==[0,0]
 assert sp['restored']==en['restored']==1 and sp['clock_before']==sp['clock_after']and sp['pins_before']==sp['pins_after']and en['before']==en['after']and en['DFS_before']==en['DFS_after']
 assert r['transaction_count']==9 and r['pmic_count']==3 and r['client_before']==r['client_after']==[1800,7,0x80000000]
 for tx in r['transactions']:assert tx['operation_code']==tx['restore_error']==0 and tx['restored']==1 and tx['register_write_attempts']==14 and tx['completion']==0x10101
 assert [q['pmic_status_raw']for q in r['PMIC']]==[0x43,0xc7,0x43]and t['powered_PMIC']['pmic_status_raw']==0xc7
 for k in ['1','2']:
  q=n['captures'][k];assert q['pmic_status_raw']==0x43 and q['configuration']==[8,7,0,0,7,7,0,0]and q['observer_READ_commands']==5
 before=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];after=json.loads(n['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert before==after and len(after)==50
 assert json.loads(n['jobs']['absent-end']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}and n['jobs']['probe-end']['receipt']['detail']['cpus']==8
 assert t['wait_counts'][3]==51 and len(t['settle_samples'])==6 and t['settle_samples'][-1]['elapsed_us']<=250000
 elapsed=r['elapsed_ticks']/r['counter_frequency']*1000;assert 5000<=elapsed<9000
 summaries.append({'point':label,'raw':[c['X'],c['Y']],'Id':c['Id'],'Type':c['Type'],'header_body_checksum_valid':True,'milliseconds':elapsed,'IRQ_before':t['IRQ_before'],'IRQ_after':t['IRQ_after'],'baseline_restored_driver_absent':True})
assert len(sessions)==1
for filename,cases in [('model.json',2271),('adapter-policy.json',202),('ABI-model.json',12),('contact-window-model.json',260),('stock-decoder-model.json',6204)]:
 q=j(E/filename);assert q['passed']and q['cases']==cases
 if isinstance(q.get('source_sha256'),dict):
  for name,d in q['source_sha256'].items():assert sha(X/name)==d
assert j(E/'adapter-policy.json')['adapter_sha256']==sha(X/'g52_driver.c')and j(E/'ABI-model.json')['source_sha256']==sha(X/'g52_client.go')
assert j(E/'contact-window-model.json')['touch_sha256']==sha(X/'g52_touch.c')
for row in build['ARM64_compilation']['objects']:assert sha(X/row['source'])==row['source_sha256']
for name,d in build['ARM64_compilation']['headers'].items():assert sha(X/name)==d
assert len(build['ARM64_compilation']['objects'])==9 and sha(X/'g52_client.go')==build['Go_client']['source_sha256']
delta=j(E/'delta-audit.json');assert delta['passed']
# Unused polling prototypes are deliberately not curated into the native milestone.
for name,d in delta['new_sha256'].items():
 if(X/name).exists():assert sha(X/name)==d
orient=j(E/'orientation.json');assert orient['passed']and orient['display_horizontal_raw_axis']=='Y'and orient['display_horizontal_positive']and orient['display_vertical_raw_axis']=='X'and not orient['display_vertical_positive']
assert not any(orient[k]for k in ['absolute_edge_calibration_qualified','continuous_tracking_release_multitouch_qualified','live_Windows_HID_input_qualified','outer_screen_qualified'])
for label,c in orient['captures'].items():assert c['decoded_sha256']==sha(E/(label+'-decoded.json'))
note=j(E/'physical-placement-note.json');assert note['user_reported_actual_inward_inches_approximately']==1 and note['equivalent_cm']==2.54 and not note['orientation_result_changed']
assert orient['actual_corner_placement']['source_note_sha256']==sha(E/'physical-placement-note.json')
for label in ['upper-left','upper-right']:assert j(E/('native-'+label+'.json'))['physical_test_actual_placement_correction']==note
repro=j(E/'source-object-reproduction.json');assert repro['all9_normalized_ARM64_objects_identical']and repro['Go_ARM64_client_byte_identical']
out={'passed':True,'same_boot_native_captures':3,'captured_contacts':summaries,'provisional_display_horizontal':'raw_Y/24400','provisional_display_vertical':'1-raw_X/22680','corner_actual_placement_approximately_inches':1,'all_three_baselines_restored_and_driver_absent':True,'contact_packet_checksums_independently_recomputed':True,'IRQ_delivery_continuous_input_release_multitouch_outer_screen_or_precise_calibration_claimed':False,'native_commands_submitted_by_audit':0}
a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
