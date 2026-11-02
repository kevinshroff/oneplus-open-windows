"""Audit G40's preserved vote failure and separate read-only recovery evidence."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G40';X=R/'experiments/G40-irq-and-history';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');r=n['trial'];assert n['outcome']=='probe_not_completed'and not n['safe_exit_verified']
assert r['operation_code']==r['restore_error']==4 and r['restored']==r['off_verified']==r['on_verified']==0
assert r['client_before']==[1800,7,0]and r['client_on']==0x80000001 and r['client_after']==[1800,7,0x80000000]
assert r['enable_attempted']==r['release_attempted']==r['safe_release']==1
assert r['powered_hook_called']==r['touch']['command_attempted']==r['spi']['vote_dirty']==0
assert r['RSC_uncertain']==r['observer_uncertain']==0 and r['transaction_count']==9 and r['pmic_count']==1
assert r['guards_before']==r['guards_after']==[1,0,0x201,0,1,0,0xe2,0]
for t in r['transactions']:assert t['operation_code']==t['restore_error']==0 and t['restored']==1 and t['completion']==0x10101 and t['register_write_attempts']==14
assert sum(t['register_reads']for t in r['transactions'])==619
recovery=j(E/'vote-recovery.json');assert recovery['phase']=='independent_off43_verified_fixed49_match_history7_unloaded_healthy8CPUs'and recovery['original_trial_flags_preserved']
assert recovery['extra_supply_votes']==recovery['SPI_commands']==recovery['reboot_commands']==0
pmic=recovery['PMIC'];assert pmic['attempt']==2 and pmic['operation_code']==0 and pmic['pmic_status_raw']==0x43 and pmic['configuration']==[8,7,0,0,7,7,0,0]
before=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];after=recovery['fixed_snapshot']['values'];assert [i for i,(x,y)in enumerate(zip(before,after))if x!=y]==[12]and before[12]['value']==0 and after[12]['value']==7
denied=json.loads(recovery['jobs']['consumed-trial-denial']['receipt']['output'])['result'];assert denied['passed']and denied['RSC_transactions']==0 and denied['map_calls_before']==denied['map_calls_after']==42
assert json.loads(recovery['jobs']['absent']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}
assert recovery['jobs']['probe-end']['receipt']['detail']['cpus']==8
rep=j(E/'power-failure-replay.json');assert rep['passed']and rep['events']==794 and rep['reads']==663 and rep['writes']==131 and rep['native_state_sha256']==sha(E/'native-evidence.json')
for f,d in rep['source_sha256'].items():assert sha(X/f)==d
model=j(E/'model.json');assert model['passed']and model['cases']==1615
for f,d in model['source_sha256'].items():assert sha(X/f)==d
assert j(E/'source-irq.json')['cases']==9 and j(E/'fixed-guard-tests.json')['cases']==1574 and j(E/'source-binding.json')['cases']==17 and j(E/'ABI-model.json')['cases']==11
build=j(E/'build.json');assert j(E/'source-object-reproduction.json')['all8_normalized_ARM64_objects_identical']
for row in build['ARM64_compilation']['objects']:assert sha(X/row['source'])==row['source_sha256']
assert sha(X/'g40_driver.c')==j(E/'fixed-guard-tests.json')['adapter_sha256']
sig=j(E/'signature-verification.json');assert sig['signed_driver_sha256']==n['driver_sha256']and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and not sig['production_trust_or_WHQL_claimed']
report={'passed':True,'native_power_trials':1,'native_SPI_commands':0,'RSC_transactions_completed_reclaimed':9,'original_raw_vote_mismatch_flags_preserved':True,'raw_enable0_to80000000_not_called_exact_restore':True,'independent_off43_configuration_verified':True,'fixed49_preserved_history0_to7_reported':True,'no_reboot_or_extra_vote_for_recovery':True,'same_session_service_endpoint_absent_control8CPUs':True,'actual_core_failure_replay_events':794,'IRQ_transfer_path_native_qualified':False,'all21_goal_areas_active':True,'scope':'Offline native/source consistency, no phone commands.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
