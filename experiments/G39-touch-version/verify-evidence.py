"""Verify the failed native G39 attempt and separately recorded reboot recovery."""
from pathlib import Path
import argparse,hashlib,json,re
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G39';X=R/'experiments/G39-touch-version';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');assert n['outcome']=='probe_not_completed'and n['safe_exit_verified']is False
t=n['trial'];touch=t['touch'];receipt=n['jobs']['touch-version-trial']['receipt'];assert receipt['status']=='error'and receipt['exit_code']==1
assert n['max_power_trials']==n['max_SPI_commands']==n['max_enable_messages']==n['max_release_messages']==1
assert t['operation_code']==6 and t['restore_error']==7 and t['restored']==t['safe_release']==t['release_attempted']==0
assert t['enable_attempted']==t['on_verified']==t['powered_hook_called']==1 and t['transaction_count']==5
assert t['client_before']==[1800,7,0x80000000]and t['client_on']==0x80000001
for r in t['transactions']:assert r['restored']==1 and r['operation_code']==r['restore_error']==0 and r['completion']==0x10101 and r['register_write_attempts']==14
assert sum(r['register_reads']for r in t['transactions'])==344
assert [r['pmic_status_raw']for r in t['PMIC']]==[0x43,0xc7]and touch['powered_PMIC']['pmic_status_raw']==0xc7
assert touch['operation_code']==8 and touch['restore_error']==1 and touch['restored']==touch['bus_quiescent']==0
assert touch['command_attempted']==touch['cancel_sent']==1 and touch['abort_sent']==0
assert touch['step_code']==-5 and touch['state']==6 and touch['tx_done']==36 and touch['rx_done']==0
assert touch['wire_TX']==[0xf1,0,1,0,0x14,255,255,255]+[0]*28 and touch['wire_RX']==[0]*36
assert touch['transport_ok']==touch['identity_ok']==0 and touch['pins_on']==[0x281,3,0xe2,0,0x2c0,3,0xe2,0,0xc0,0,0xe2,0]
events=touch['trace'];assert len(events)==101 and touch['register_reads']==72 and touch['register_write_attempts']==29
assert any(e['kind']==1 and e['address']=='0xa90610'and e['value']==0x80 for e in events)
assert events[-2:]==[{'kind':1,'address':'0xa90610','value':0x0c200011},{'kind':1,'address':'0xa90040','value':0}]
assert not any(e['kind']==2 and e['address']=='0xa90618'and e['value']==0x0c200011 for e in events)
assert len([e for e in events if e['kind']==2 and e['address']=='0xa90600'])==1
for f in['geni_fifo.c','geni_fifo.h']:assert(X/f).read_bytes()==(R/'experiments/G27-spi-core'/f).read_bytes()
model=j(E/'model.json');assert model['passed']and model['cases']==1609
for f,digest in model['source_sha256'].items():assert sha(X/f)==digest
assert j(E/'ABI-model.json')['cases']==11 and j(E/'source-binding.json')['cases']==17
replay=j(E/'touch-failure-replay.json');assert replay['passed']and replay['native_touch_events']==101 and replay['native_state_sha256']==sha(E/'native-evidence.json')
for f,digest in replay['source_sha256'].items():assert sha(X/f)==digest
health=j(E/'post-probe-health.json')['receipt'];assert health['status']=='ok'and health['detail']['cpus']==8 and health['session']==n['phone_session']
recovery=j(E/'recovery.json');assert recovery['SPI_commands_after_trial']==0 and recovery['consuming_RX_words']==1 and recovery['partial_RX_valid_bytes']==[0,0,0]
assert recovery['jobs']['normal-reboot']['receipt']['status']=='ok'
protected=j(E/'protected-reboot-verification.json');assert protected['session']!=n['phone_session']and protected['all_six_GPTs_byte_identical']and protected['partition_count']==138 and protected['original_DSDT_active']
assert all(d['byte_identical_regions']==5 for d in protected['GPT_checks'])
for part,digest in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:assert protected[part]['sha256']==digest and protected[part]['raw_writes']==0
old=j(E/'old-observer-reboot-refusal.json');values=old['snapshot_before']['values'];assert values[12]=={'address':'0x17a20d44','name':'CMD0_RESP_DATA','value':0}
prior=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];assert len(values)==len(prior)==50
assert [i for i,(x,y)in enumerate(zip(values,prior))if x!=y]==[12]
assert not old['fixed50_match_before']and 'one-PMIC-off-capture'not in old['jobs']
for label in['G39-absent','G35-absent-end']:assert json.loads(old['jobs'][label]['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}
assert old['jobs']['probe-end']['receipt']['detail']['cpus']==8
debug=(E/'post-reboot-debug.txt').read_text();assert re.search(r'a90800 00000000 00000000',debug)and '152008 40002380'in debug
assert sha(E/'post-reboot-debug.txt')==recovery['jobs']['post-reboot-debug-log-get']['receipt']['sha256']
assert sha(E/'retained-state-debug.txt')==recovery['jobs']['log-get']['receipt']['sha256']
for relative,digest in j(E/'curation-manifest.json')['files'].items():assert sha(R/relative)==digest
sig=j(E/'signature-verification.json');assert sig['signed_driver_sha256']==n['driver_sha256']and sig['SHA256_Authenticode_digest_matches_verified_CMS_content']and not sig['production_trust_or_WHQL_claimed']
report={'passed':True,'native_touch_commands':1,'cancel_commands':1,'abort_commands':0,'physical_identity_or_touch_qualified':False,'original_failure_flags_preserved':True,'actual_touch_core_failure_replay_events':101,'target_healthy_before_deliberate_debugger_break':True,'normal_G17_reboot_and_protected_baselines_verified':True,'post_reboot_fixed49_match_and_read_only_history7_to0':True,'old_PMIC_guard_refused_before_commands':True,'new_post_reboot_PMIC_capture_claimed':False,'all21_goal_areas_active':True,'scope':'Offline source/native-receipt consistency; zero device actions.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
