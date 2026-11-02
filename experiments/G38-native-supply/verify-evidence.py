"""Verify saved native G38 power/source/build/failure-correction evidence."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',required=True,type=Path);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G38';X=R/'experiments/G38-native-supply';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and len(n['jobs'])==25
assert n['max_loads']==n['max_power_trials']==n['max_enable_messages']==n['max_release_messages']==1 and n['max_RSC_transactions']==9 and n['max_RSC_writes']==126
for label,row in n['jobs'].items():
 r=row['receipt'];assert row['id']==r['id']and r['session']==('00000000000000000000000000000000'if r['node']=='host'else n['phone_session'])
 assert (r['status']=='error'and r['exit_code']==1)if label=='two-capture-limit'else(r['status']=='ok'and r.get('exit_code',0)==0)
def result(label):q=json.loads(n['jobs'][label]['receipt']['output']);assert q['ok'];return q['result']
assert result('load')['start_success']and result('load')['state']==4 and result('load')['driver_sha256']==n['driver_sha256']
for label in['G37-absent','absent-stage','absent-end']:assert result(label)=={'device_absent':True,'service_absent':True}
assert result('probe-loaded')['map_calls']==0 and result('probe-loaded')['build_id']=='G38-rsc-pwr-1'
t=result('selftest');assert t['passed']and len(t['cases'])==14 and t['map_calls_before']==t['map_calls_after']==0
prior=j(R/'evidence/G37/native-evidence.json');base=json.loads(prior['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert n['phone_session']==prior['phone_session']
for key,maps in[('snapshot-before',4),('snapshot-after',54)]:
 r=result(key);assert r['values']==base and r['status']['map_calls']==maps and r['register_writes']==0
for index,maps,reads in[(1,18,44),(2,50,41)]:
 r=result('pmic-'+str(index));assert r['operation_code']==0 and r['fixed_registers_unchanged']==1 and r['pmic_status_raw']==0x43 and r['configuration']==[8,7,0,0,7,7,0,0]and r['status']['map_calls']==maps and r['register_reads']==reads and r['observer_READ_commands']==r['observer_write_attempts']==5
r=result('power-trial');assert r['operation_code']==r['restore_error']==r['RSC_uncertain']==r['observer_uncertain']==0
for k in['restored','fixed_registers_unchanged','attempt','enable_attempted','release_attempted','preflight_verified','on_verified','off_verified']:assert r[k]==1
assert r['status']['map_calls']==36 and r['transaction_count']==9 and r['pmic_count']==3 and r['client_before']==r['client_after']==[1800,7,0x80000000]and r['client_on']==0x80000001
assert r['guards_before']==r['guards_after']==[1,0,0x201,0,1,0,0xe2,0]and r['waits_1ms']==9 and r['waits_10ms']==2
expected=[('0x40800',0x108,0),('0x40808',0x108,0),('0x40804',0x108,0),('0x40804',0x10108,1),('0x40804',0x108,0),('0x40804',0x10108,0),('0x40804',0x108,0),('0x40800',0x108,0),('0x40808',0x108,0)]
for t,request in zip(r['transactions'],expected):
 assert (t['request_address'],t['message_id'],t['request_data'])==request and t['operation_code']==t['restore_error']==0 and t['restored']==t['trigger_attempted']==1 and t['completion']==0x10101 and t['register_write_attempts']==14
 assert len(t['trace'])==t['register_reads']+14
old=j(R/'evidence/G33/trial/native-result.json');assert not old['success']and old['needs_recovery']
historical=[(e['address'],e['value'])for e in old['events']if e['kind']=='write_attempt'and 0x17a20000<=e['address']<0x17a22000]
actual=[(int(e['address'],16),e['value'])for t in r['transactions']for e in t['trace']if e['kind']==2];assert len(actual)==126 and actual==historical
for index,t in enumerate(r['PMIC']):
 assert t['operation_code']==0 and t['observer_READ_commands']==t['observer_write_attempts']==5 and t['completion']==[1]*5 and t['pmic_status_raw']==[0x43,0xc7,0x43][index]
 assert t['configuration']==([8,7,8,7,7,7,128,0]if index==1 else[8,7,0,0,7,7,0,0])
for label,maps in[('power-limit',36),('two-capture-limit-v2',50)]:
 t=result(label);assert t['passed']and t['denied_code']==1002 and t['map_calls_before']==t['map_calls_after']==maps
bad=json.loads(n['jobs']['two-capture-limit']['receipt']['output']);assert not bad['ok']and bad['result']['operation_code']==1002 and bad['result']['trace']==[]and bad['result']['register_reads']==bad['result']['observer_write_attempts']==bad['result']['observer_READ_commands']==0
assert result('stop')=={'stopped':True,'delete_requested':True}and n['jobs']['probe-end']['receipt']['detail']['cpus']==8
model=j(E/'model.json');assert model['passed']and model['cases']==1019 and model['all126_RSC_writes_identical_to_G33_native_recording']
for name,digest in model['source_sha256'].items():assert sha(X/name)==digest
for name,digest in j(E/'source-build-audit.json')['source_sha256'].items():assert sha(X/name)==digest
rep=j(E/'power-native-replay.json');off=j(E/'off-native-replay.json');assert rep['passed']and rep['events']==891 and rep['all_actual_C_cores_and_output_fields']and off['passed']and sum(c['events']for c in off['captures'])==95
assert rep['native_state_sha256']==off['source_native_state_sha256']==sha(E/'native-evidence.json')
b=j(E/'build.json');assert b['client_v1']['output_sha256']==n['client_sha256']and b['client_v2']['output_sha256']==n['corrected_client_sha256']
assert b['client_v1']['source_sha256']==sha(X/'g38_client-v1.go')and b['client_v2']['source_sha256']==sha(X/'g38_client.go')
sig=j(E/'signature-verification.json');assert sig['signed_driver_sha256']==n['driver_sha256']and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and not sig['production_trust_or_WHQL_claimed']
fix=j(E/'client-budget-fix.json');assert fix['driver_unchanged']and fix['supply_cycle_not_replayed']and fix['patch_sha256']==sha(X/'client-budget-fix.patch')
report={'passed':True,'native_power_trials':1,'RSC_transactions':9,'supply_enable_release_one_each':True,'full_raw_status43_c7_43_and_configuration_verified':True,'client_votes_and_all50_platform_words_restored':True,'all126_RSC_writes_match_G33_native':True,'recorded_core_events_exact_replay':986,'model_cases':1019,'client_false_negative_preserved_and_corrected_without_power_replay':True,'driver_service_endpoint_removed_control8CPUs':True,'actual_SPI_or_touch_qualification':False,'all21_goal_areas_active':True,'scope':'Offline native-receipt/source consistency; no target commands.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in['passed','native_power_trials','RSC_transactions','recorded_core_events_exact_replay']}))
