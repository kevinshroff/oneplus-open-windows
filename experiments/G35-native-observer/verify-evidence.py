"""Check G35 receipts/source/provenance offline; never execute target commands."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
R=a.repository;E=R/'evidence/G35';X=R/'experiments/G35-native-observer';read=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=read(E/'native-evidence.json');assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and n['max_loads']==1 and n['max_PMIC_captures']==2 and len(n['jobs'])==20
for row in n['jobs'].values():
 r=row['receipt'];assert row['id']==r['id']and r['status']=='ok'and r.get('exit_code',0)==0
 assert r['session']==('00000000000000000000000000000000'if r['node']=='host'else n['phone_session'])
def result(key):
 q=json.loads(n['jobs'][key]['receipt']['output']);assert q['ok'];return q['result']
def status(s):
 assert (s['size'],s['version'],s['magic'],s['build_id'])==(80,1,'0x314f52463533474f','G35-kmdf-obs1')
 assert (s['kernel_build'],s['processors'],s['irql'],s['register_count'])==(26100,8,0,50)
 assert (s['firmware_bytes'],s['firmware_match'],s['firmware_status'])==(576,1,'0x0')
assert result('G34-absent')==result('absent-stage')==result('absent-end')=={'device_absent':True,'service_absent':True}
load=result('load');assert load['start_success']and load['state']==4 and load['driver_sha256']==n['driver_sha256']
probe=result('probe-loaded');status(probe);assert probe['map_calls']==0
t=result('selftest');status(t['status']);assert t['passed']and t['map_calls_before']==t['map_calls_after']==0 and len(t['cases'])==13
cases={x['case']:x['expected_error']for x in t['cases']};assert cases=={'long-input':87,'wrong-size':87,'wrong-version':87,'empty-output':122,'empty-input':87,'short-input':87,'wrong-magic':87,'short-status-output':122,'short-snapshot-output':122,'unknown-ioctl':1,'short-pmic-output':122,'exclusive-open':5,'anonymous-open':5}
baseline=read(E/'observer-binding.json')['expected_50_values'];assert len(baseline)==50
g34=read(R/'evidence/G34/native-evidence.json');assert n['phone_session']==g34['phone_session']
assert baseline==json.loads(g34['jobs']['cycle2-snapshot-B']['receipt']['output'])['result']['values']
for key,count in [('snapshot-before',4),('snapshot-after',36)]:
 r=result(key);status(r['status']);assert r['status']['map_calls']==count and r['values']==baseline and r['fixed_register_reads']==50 and r['register_writes']==0
captures=[]
expected_writes=[('0xc440ea0',0x08000007),('0xc441220',0x08000007),('0xc4456e0',0x08000007),('0xc4456e0',0x08000080),('0xc4456e0',0x08000407)]
for index in [1,2]:
 r=result('pmic-'+str(index));status(r['status']);assert r['operation_code']==r['stage']==0 and r['fixed_registers_unchanged']==1 and r['attempt']==index
 assert r['observer_READ_commands']==r['observer_write_attempts']==5 and r['completion']==[1]*5
 assert r['register_reads']==44 and r['polls']==13 and r['status']['map_calls']==4+14*index
 assert r['revision']==[32,0,0,2,81,73,1,0]and r['anchor']==[0,4,1,1,4,172,0,0]and r['identity']==[0,4,1,1,4,171,0,0]
 assert r['pmic_status_raw']==0x43 and r['configuration']==[8,7,0,0,7,7,0,0]
 assert len(r['trace'])==49 and sum(x['kind']==1 for x in r['trace'])==44
 writes=[(x['address'],x['value'])for x in r['trace']if x['kind']==2];assert writes==expected_writes and all(value>>27==1 for _,value in writes)
 assert r['counter_frequency']==19200000 and r['elapsed_ticks']>0
 captures.append({'capture':index,'reads':44,'observer_READ_commands':5,'polls':13,'PMIC_status':67,'configuration_off':True,'fixed_50_register_guard_unchanged':True,'elapsed_ticks':r['elapsed_ticks'],'frequency':r['counter_frequency'],'elapsed_us_including_map_and_guards':r['elapsed_ticks']*1e6/r['counter_frequency']})
budget=result('two-capture-limit');assert budget=={'passed':True,'denied_code':1002,'map_calls_before':32,'map_calls_after':32,'observer_READ_commands':0}
assert result('stop')=={'stopped':True,'delete_requested':True}
health=n['jobs']['probe-end']['receipt']['detail'];assert health['cpus']==8 and health['arch']=='arm64'
build=read(E/'build.json');audit=read(E/'source-build-audit.json');model=read(E/'observer-model.json');replay=read(E/'native-replay.json');signature=read(E/'signature-verification.json');sign=read(E/'signing-evidence.json')
for name,value in audit['fixed_source_files'].items():assert sha(X/name)==value
assert build['client']['output_sha256']==build['client_repeated']['output_sha256']==n['client_sha256']
assert build['client']['source_sha256']==sha(X/'g35_client.go')
assert [x['sha256']for x in build['compile']['objects']]==[x['sha256']for x in build['compile_repeated']['objects']]
for row in build['compile']['objects']:assert row['source_sha256']==sha(X/row['source'])
assert model['passed']and model['cases']==116 and model['source_sha256']==sha(X/'g35_observer.c')
assert replay['passed']and replay['core_sha256']==sha(X/'g35_observer.c')and sum(x['events']for x in replay['captures'])==98
assert signature['signed_driver_sha256']==n['driver_sha256']and signature['SHA256_Authenticode_digest_matches_verified_CMS_content']and signature['all_loadable_sections_byte_identical_before_after_signing']
assert not signature['production_trust_or_WHQL_claimed']and not signature['root_trust_store_changed']
assert sign['metadata']['certificate_thumbprint']==read(R/'evidence/G34/signing-evidence.json')['metadata']['certificate_thumbprint']
report={'passed':True,'phone_session':n['phone_session'],'load_unload_cycles':1,'native_guard_checks':13,'captures':captures,'native_observer_reads':88,'native_observer_READ_command_writes':10,'native_trace_events':98,'two_capture_limit_no_MMIO':True,'two_external_50_word_snapshots_match_G34':True,'service_device_absent_control8CPUs_final':True,'PMIC_status_bit6_resolved':False,'production_trust_claimed':False,'limits':['Observer command history changes normally; PMIC config and supply votes are never written.','Temporary non-PnP diagnostic does not establish general Windows resource ownership.','Recorded durations include mappings and baseline checks; no real-time latency guarantee.','The G33 whole-status restore failure remains unchanged and unresolved.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','native_guard_checks','native_trace_events','two_capture_limit_no_MMIO','PMIC_status_bit6_resolved']}))
