"""Offline audit of G41 identity, guarded cleanup failures, and separate G45 recovery."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'G41/native-evidence.json');r=n['trial'];t=r['touch'];assert n['outcome']=='identity_verified'and not n['safe_exit_verified']
assert sha(E/'G41/native-evidence.json')=='61d6114a301fbb783956984a8673056d8ac0fc05431532590d1d090c61c6824e'
assert r['operation_code']==6 and r['restore_error']==7 and r['restored']==r['safe_release']==r['off_verified']==0
assert r['transaction_count']==5 and r['release_attempted']==0 and r['on_verified']==1 and r['RSC_uncertain']==r['observer_uncertain']==0
assert t['transport_ok']==t['identity_ok']==t['command_attempted']==1 and t['operation_code']==0 and t['restore_error']==1 and t['restored']==t['bus_quiescent']==0
assert t['tx_done']==t['rx_done']==36 and t['cancel_sent']==t['abort_sent']==0
assert t['ROM_PID']=='BERLIN'and t['patch_PID']=='9966'and t['ROM_VID']==[1,0,5]and t['patch_VID']==[0x83,0x49,3,0x2f]and t['sensor_id']==255
wire=t['wire_RX'];assert len(wire)==36 and sum(wire[8:34])==int.from_bytes(bytes(wire[34:36]),'little')==1181
assert len(t['trace'])==147 and t['register_reads']==105 and t['register_write_attempts']==42
rep=j(E/'G41/touch-replay.json');assert rep['passed']and rep['native_touch_events']==147 and rep['native_state_sha256']==sha(E/'G41/native-evidence.json')
assert sha(E/'G41/held-debug.txt')=='049a535551736255f404e7ebd9e4105efd5151d950996be89ae15da6716ed9b7'
assert j(E/'G41/model.json')['cases']==1617 and j(E/'G41/source-binding.json')['cases']==17 and j(E/'G41/source-irq.json')['cases']==9
for tag,code,write_count in [('G42',103,0),('G43',105,0),('G44',105,2)]:
 s=j(E/tag/'native-evidence.json');q=s['recovery'];assert not s['safe_exit_verified']and q['operation_code']==code and q['transaction_count']==q['release_attempted']==q['safe_release']==0
 assert q['touch']['register_write_attempts']==write_count and q['spi']['register_write_attempts']==q['spi']['engine']['register_write_attempts']==0
 assert q['touch']['powered_PMIC']['pmic_status_raw']==0xc7
 if tag=='G42':assert q['spi']['trace'][2]=={'address':'0x1184f0','kind':1,'value':0}
 if tag=='G43':assert q['touch']['pins_on'][9]==1 and q['touch']['operation_code']==1
 if tag=='G44':
  writes=[x for x in q['touch']['trace']if x['kind']==2];assert writes==[{'address':'0xa90648','kind':2,'value':0x0c000000},{'address':'0xa90618','kind':2,'value':0x80}]
  assert q['touch']['trace'][-1]=={'address':'0xa90610','kind':1,'value':0x80}
s=j(E/'G45/native-evidence.json');r=s['recovery'];t=r['touch'];sp=r['spi'];en=sp['engine'];assert s['safe_exit_verified']and s['phase']=='cleanup_complete_service_endpoint_absent_control8CPUs_same_session'and s['phone_session']==n['phone_session']
assert r['operation_code']==r['restore_error']==r['enable_attempted']==r['RSC_uncertain']==r['observer_uncertain']==0 and r['restored']==r['off_verified']==r['safe_release']==r['restored_fixed_baseline']==r['release_attempted']==1
assert r['client_before']==r['client_after']==[1800,7,0x80000000]and r['client_on']==0x80000001
assert r['transaction_count']==4 and r['pmic_count']==1 and r['PMIC'][0]['pmic_status_raw']==0x43 and r['PMIC'][0]['configuration']==[8,7,0,0,7,7,0,0]
assert t['restored']==t['bus_quiescent']==sp['restored']==en['restored']==1 and t['command_attempted']==t['transport_ok']==t['identity_ok']==t['tx_done']==t['rx_done']==0
assert t['pins_before']==t['pins_after']and t['lengths_before']==t['lengths_after']==[0,0]and sp['clock_before']==sp['clock_after']and sp['pins_before']==sp['pins_after']and en['before']==en['after']and en['DFS_before']==en['DFS_after']
assert en['guards_after'][1]in[0,0x80]and not(en['after'][23]&0x80)
for tx in r['transactions']:assert tx['operation_code']==tx['restore_error']==0 and tx['restored']==1 and tx['completion']==0x10101 and tx['register_write_attempts']==14
writes=[x for key in[t,sp,en,t['powered_PMIC'],*r['PMIC'],*r['transactions']]for x in key['trace']if x['kind']==2]
assert not any(x['address']in['0xa90600','0xa90604','0xa90700','0xa90618','0xa90648']or(x['address']=='0x17a20d3c'and x['value']==1)for x in writes)
used=json.loads(s['jobs']['used-cleanup-denied']['receipt']['output'])['result'];assert used['passed']and used['RSC_transactions']==0 and used['map_calls_before']==used['map_calls_after']==28
before=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];after=json.loads(s['jobs']['baseline-after']['receipt']['output'])['result']['values'];assert before==after
assert json.loads(s['jobs']['absent-end']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}and s['jobs']['probe-end']['receipt']['detail']['cpus']==8
replay=j(E/'G45/native-replay.json');assert replay['passed']and replay['all7_actual_C_cores_and_all_result_bytes']and replay['native_state_sha256']==sha(E/'G45/native-evidence.json')
for tag,experiment in [('G41','G41-touch-identity'),('G42','G42-held-cleanup'),('G43','G43-held-cleanup'),('G44','G44-held-cleanup'),('G45','G45-held-cleanup')]:
 X=R/'experiments'/experiment;build=j(E/tag/'build.json');model=j(E/tag/'model.json')
 for f,d in model['source_sha256'].items():assert sha(X/f)==d
 for obj in build['ARM64_compilation']['objects']:assert sha(X/obj['source'])==obj['source_sha256']
 sig=j(E/tag/'signature-verification.json');assert sig['signed_driver_sha256']==j(E/tag/'native-evidence.json')['driver_sha256']and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and not sig['production_trust_or_WHQL_claimed']
 assert j(E/tag/'ABI-model.json')['cases']==11
for tag,experiment in [('G41','G41-touch-identity'),('G45','G45-held-cleanup')]:
 X=R/'experiments'/experiment;rep=j(E/tag/('touch-replay.json'if tag=='G41'else'native-replay.json'))
 for name,d in rep['source_sha256'].items():assert sha(X/name)==d
 proof=j(E/tag/'source-object-reproduction.json');assert proof['passed']and proof['all8_normalized_ARM64_objects_identical']and proof['Go_ARM64_client_byte_identical']and proof['client_sha256']==j(E/tag/'native-evidence.json')['client_sha256']
assert j(E/'G45/model.json')['cases']==829 and j(E/'G45/adapter-policy.json')['cases']==74 and j(E/'G45/held-guard-tests.json')['cases']==1605 and j(E/'G45/IRQ-guard-tests.json')['cases']==387
report={'passed':True,'native_Goodix_9966_identity_verified':True,'ROM_PID':'BERLIN','patch_PID':'9966','version_checksum':1181,'identity_touch_events_replayed':147,'original_failed_G41_cleanup_flags_preserved':True,'G42_G43_no_restore_or_release_writes':True,'G44_two_IRQ_ACKs_only_then_hold':True,'G45_new_SPI_enable_and_IRQ_ACK_commands':0,'G45_release_transactions_completed_reclaimed':4,'G45_off43_and_original_configuration_verified':True,'masked_M80_raw_status_not_claimed_cleared':True,'same_session_8CPU_control_and_no_temporary_endpoint':True,'working_touch_or_screen_mapping_claimed':False,'all21_goal_areas_active':True,'scope':'Offline source/evidence consistency only; no hardware actions.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
