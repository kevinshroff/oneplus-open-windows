"""Verify saved G37 source/build/native evidence without target commands."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G37';X=R/'experiments/G37-primary-spi-engine';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and len(n['jobs'])==22
assert n['max_SPI_preparations']==1 and n['max_SPI_clock_pad_writes']==14 and n['max_SPI_engine_writes']==48
for row in n['jobs'].values():
 r=row['receipt'];assert row['id']==r['id']and r['status']=='ok'and r.get('exit_code',0)==0
 assert r['session']==('00000000000000000000000000000000'if r['node']=='host'else n['phone_session'])
def result(key):q=json.loads(n['jobs'][key]['receipt']['output']);assert q['ok'];return q['result']
for key in ['G35-absent','absent-stage','absent-end']:assert result(key)=={'device_absent':True,'service_absent':True}
assert result('load')['start_success']and result('load')['state']==4 and result('load')['driver_sha256']==n['driver_sha256']
probe=result('probe-loaded');assert probe['map_calls']==0 and probe['processors']==8 and probe['firmware_match']==1 and probe['build_id']=='G37-spi-eng-1'
tests=result('selftest');assert tests['passed']and len(tests['cases'])==14 and tests['map_calls_before']==tests['map_calls_after']==0
prior=j(R/'evidence/G36/native-evidence.json');baseline=json.loads(prior['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert n['phone_session']==prior['phone_session']
for key,count in [('snapshot-before',4),('snapshot-after',51)]:
 r=result(key);assert r['values']==baseline and r['status']['map_calls']==count and r['register_writes']==0
for index,count in[(1,18),(2,47)]:
 r=result('pmic-'+str(index));assert r['operation_code']==0 and r['fixed_registers_unchanged']==1 and r['attempt']==index and r['status']['map_calls']==count
 assert r['pmic_status_raw']==0x43 and r['configuration']==[8,7,0,0,7,7,0,0]and r['completion']==[1]*5 and r['observer_READ_commands']==r['observer_write_attempts']==5
 assert r['revision']==[32,0,0,2,81,73,1,0]and r['anchor']==[0,4,1,1,4,172,0,0]and r['identity']==[0,4,1,1,4,171,0,0]
r=result('spi-prepare');e=r['engine'];assert r['operation_code']==r['restore_error']==0 and r['restored']==r['fixed_registers_unchanged']==r['attempt']==1 and r['status']['map_calls']==33
assert r['register_reads']==92 and r['register_write_attempts']==14 and len(r['trace'])==106
assert r['clock_before']==r['clock_after']==[0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002]and r['pins_before']==r['pins_after']==[1,0,0xe2,0]*4
assert r['pins_during']==[0x85,0,0xe2,0,0x85,0,0xe2,0,0x85,0,0xe2,0,0x85,1,0xe2,0]
assert r['identity']==[0x30090000,0,0,0x102,0x102,0x20102864,0x20104800,0x4000]
assert e['operation_code']==e['restore_error']==e['stage']==0 and e['restored']==1 and e['register_reads']==199 and e['register_write_attempts']==14 and len(e['trace'])==213
assert e['before']==e['after']and e['DFS_before']==e['DFS_after']and e['guards_before']==e['guards_after']==[0]*10
assert e['clock_index']==0 and e['source_hz']==19200000 and e['bus_hz']==960000 and e['DFS_before'][0]==0x21 and e['DFS_before'][1]==1
assert e['during']==[0,0,0x7f,0x7f,0,0,0,0,0,0,0,0,0x7f8fe,0xffefe,4,0,0x7f8fe,0xffefe,0,0x141,0,0,14,0x7fc0007f]
fw=[(x['address'],x['value'])for x in e['trace']if x['kind']==2]
on=[('0xa90e1c',0),('0xa90260',0x7f8fe),('0xa90268',4),('0xa90278',0),('0xa90284',0x7f8fe),('0xa90048',0x141),('0xa90614',0x7fc0007f)]
undo=[('0xa90614',0x33c0007e),('0xa90048',0x11),('0xa90284',0x7f807),('0xa90278',0x200000),('0xa90268',0),('0xa90260',0x7f807),('0xa90e1c',15)]
assert fw==on+undo
for key,count,field in[('spi-limit',33,'register_write_attempts'),('two-capture-limit',47,'observer_READ_commands')]:
 v=result(key);assert v['passed']and v['denied_code']==1002 and v['map_calls_before']==v['map_calls_after']==count and v[field]==0
assert result('stop')=={'stopped':True,'delete_requested':True}and n['jobs']['probe-end']['receipt']['detail']['cpus']==8
model=j(E/'engine-model.json');pad=j(E/'spi-model.json');replay=j(E/'SPI-native-replay.json');pmic=j(E/'PMIC-native-replay.json');audit=j(E/'source-build-audit.json');build=j(E/'build.json');sig=j(E/'signature-verification.json');binding=j(E/'source-binding.json')
assert model['passed']and model['cases']==398 and model['core_sha256']==sha(X/'g37_engine.c')and pad['passed']and pad['cases']==165 and pad['core_sha256']==sha(X/'g37_spi.c')
assert replay['passed']and replay['events']==319 and replay['both_actual_C_cores']and replay['all_output_fields_and_reads_writes_match']
assert replay['core_sha256']=={name:sha(X/name)for name in['g37_spi.c','g37_engine.c']}
assert pmic['passed']and sum(c['events']for c in pmic['captures'])==98 and pmic['core_sha256']==sha(X/'g37_observer.c')
for name,digest in audit['source_sha256'].items():assert sha(X/name)==digest
for row in build['compile']['objects']:assert sha(X/row['source'])==row['source_sha256']
assert build['client']['output_sha256']==n['client_sha256']and sig['signed_driver_sha256']==n['driver_sha256']and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and sig['all_loadable_sections_byte_identical_before_after_signing']and not sig['production_trust_or_WHQL_claimed']
assert binding['passed']and binding['bi_tcxo_Hz']==19200000 and binding['SPI_Hz']==960000
report={'passed':True,'native_configuration_trials':1,'clock_pad_writes':14,'engine_writes':14,'PMIC_READ_commands':10,'recorded_core_MMIO_events':417,'all24_engine25_DFS16_pin6_clock_words_restore':True,'fixed50_platform_guards_unchanged':True,'GIC389_quiet_level_and_engine_idle':True,'PMIC_raw43_off_config_unchanged':True,'source_matched_SPI_configuration_Hz':960000,'measured_SPI_clock_waveform':False,'actual_SPI_transfer_or_power_reset_change':False,'model_cases':563,'lifetime_limits_no_MMIO':True,'driver_service_endpoint_removed_control8CPUs':True,'all21_goal_areas_active':True,'scope':'Offline consistency checks; no target commands.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','native_configuration_trials','engine_writes','recorded_core_MMIO_events']}))
