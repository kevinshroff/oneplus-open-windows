"""Verify native G36 receipts and source/model links without device access."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G36';X=R/'experiments/G36-primary-spi-prepare';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and len(n['jobs'])==22 and n['max_SPI_preparations']==1 and n['max_SPI_clock_pad_writes']==14
for row in n['jobs'].values():
 r=row['receipt'];assert row['id']==r['id']and r['status']=='ok'and r.get('exit_code',0)==0;assert r['session']==('00000000000000000000000000000000'if r['node']=='host'else n['phone_session'])
def result(key):q=json.loads(n['jobs'][key]['receipt']['output']);assert q['ok'];return q['result']
for key in ['G35-absent','absent-stage','absent-end']:assert result(key)=={'device_absent':True,'service_absent':True}
load=result('load');assert load['start_success']and load['state']==4 and load['driver_sha256']==n['driver_sha256']
probe=result('probe-loaded');assert probe['map_calls']==0 and probe['firmware_match']==1 and probe['processors']==8 and probe['build_id']=='G36-spi-pad-1'
tests=result('selftest');assert tests['passed']and tests['map_calls_before']==tests['map_calls_after']==0 and len(tests['cases'])==14
assert {x['case']for x in tests['cases']}=={'long-input','wrong-size','wrong-version','empty-output','empty-input','short-input','wrong-magic','short-status-output','short-snapshot-output','unknown-ioctl','short-pmic-output','short-spi-output','exclusive-open','anonymous-open'}
prior=j(R/'evidence/G35/native-evidence.json');baseline=json.loads(prior['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert n['phone_session']==prior['phone_session']
for key,count in [('snapshot-before',4),('snapshot-after',50)]:
 r=result(key);assert r['values']==baseline and r['status']['map_calls']==count and r['register_writes']==0
for index,count in [(1,18),(2,46)]:
 r=result('pmic-'+str(index));assert r['operation_code']==0 and r['fixed_registers_unchanged']==1 and r['attempt']==index and r['status']['map_calls']==count
 assert r['pmic_status_raw']==0x43 and r['configuration']==[8,7,0,0,7,7,0,0]and r['completion']==[1]*5 and r['observer_READ_commands']==r['observer_write_attempts']==5
 assert r['revision']==[32,0,0,2,81,73,1,0]and r['anchor']==[0,4,1,1,4,172,0,0]and r['identity']==[0,4,1,1,4,171,0,0]
r=result('spi-prepare');assert r['operation_code']==r['restore_error']==0 and r['restored']==r['fixed_registers_unchanged']==r['attempt']==1 and r['status']['map_calls']==32
assert r['register_reads']==92 and r['register_write_attempts']==14 and len(r['trace'])==106
assert r['clock_before']==r['clock_after']==[0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002]
assert r['pins_before']==r['pins_after']==[1,0,0xe2,0]*4
assert r['pins_during']==[0x85,0,0xe2,0,0x85,0,0xe2,0,0x85,0,0xe2,0,0x85,1,0xe2,0]
assert r['identity']==[0x30090000,0,0,0x102,0x102,0x20102864,0x20104800,0x4000]
writes=[(x['address'],x['value'])for x in r['trace']if x['kind']==2]
assert writes==[('0x152008',0x40102380),('0x152008',0x40302380),('0x152008',0x44302380)]+[(hex(0xf12c000+i*0x1000),0x85)for i in range(4)]+[(hex(0xf12c000+i*0x1000),1)for i in range(3,-1,-1)]+[('0x152008',0x40302380),('0x152008',0x40102380),('0x152008',0x40002380)]
assert [x['value']for x in r['trace']if x['kind']==1 and x['address']=='0x1184e4']==[0x80004000,0x80004000,0x4000,0x80004000]
for key,count,field in [('spi-limit',32,'register_write_attempts'),('two-capture-limit',46,'observer_READ_commands')]:
 b=result(key);assert b['passed']and b['denied_code']==1002 and b['map_calls_before']==b['map_calls_after']==count and b[field]==0
assert result('stop')=={'stopped':True,'delete_requested':True};health=n['jobs']['probe-end']['receipt']['detail'];assert health['cpus']==8 and health['arch']=='arm64'
model=j(E/'spi-model.json');source=j(E/'pin-source-validation.json');aop=j(E/'status-handler-emulation.json');replay=j(E/'SPI-native-replay.json');pmic=j(E/'PMIC-native-replay.json');audit=j(E/'source-build-audit.json');build=j(E/'build.json');sig=j(E/'signature-verification.json');fix=j(E/'host-validator-fix.json')
assert model['passed']and model['cases']==162 and model['core_sha256']==sha(X/'g36_spi.c')
assert source['passed']and source['cases']==34 and source['unchanged_functions']==3 and source['normal_register_value']=='0x85'
assert aop['passed']and aop['cases']==781 and aop['latched_status_mask']=='0x20'and not aop['precise_status_bit6_name_established']
assert all(c['latched_flag']==0 and c['modeled_writes']==0 for c in aop['critical_cases']if c['raw_status']in[3,0x43,0x87,0xc7])
assert replay['passed']and replay['events']==106 and replay['core_sha256']==sha(X/'g36_spi.c')and replay['all_output_fields_and_reads_writes_match']
assert pmic['passed']and sum(c['events']for c in pmic['captures'])==98 and pmic['core_sha256']==sha(X/'g36_observer.c')
for name,value in audit['source_sha256'].items():assert sha(X/name)==value
assert [o['sha256']for o in build['compile']['objects']]==[o['sha256']for o in build['compile_repeated']['objects']]
assert build['client']['output_sha256']==build['client_repeated']['output_sha256']==n['client_sha256']
assert sig['signed_driver_sha256']==n['driver_sha256']and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and not sig['production_trust_or_WHQL_claimed']
assert fix['hardware_trial_not_replayed']and fix['actual_reads']==92 and fix['incorrect_host_expected_reads']==91 and fix['native_job']==n['jobs']['spi-prepare']['id']
report={'passed':True,'phone_session':n['phone_session'],'native_SPI_preparations':1,'clock_pad_reads':92,'clock_pad_write_attempts':14,'PMIC_READ_commands':10,'recorded_MMIO_events':204,'CLK46_input':0,'CS47_input':1,'clock_pin_and_fixed50_restoration_verified':True,'PMIC_status43_off_config_unchanged':True,'lifetime_limits_pass_no_MMIO':True,'driver_service_device_removed_control8CPUs':True,'source_pin_cases':34,'core_model_cases':162,'original_AOP_status_cases':781,'host_count_assertion_corrected_without_replay':True,'SPI_transfer_or_reset_or_supply_change':False,'status_bit6_name_established':False,'scope':'Offline receipt/source consistency; no target commands.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','native_SPI_preparations','clock_pad_write_attempts','CLK46_input','CS47_input','recorded_MMIO_events']}))
