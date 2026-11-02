"""Offline audit of the actual partial IC-info read and its complete cleanup."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G46';X=R/'experiments/G46-info-header';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');r=n['trial'];t=r['touch'];sp=r['spi'];en=sp['engine'];assert n['outcome']=='header_length_captured'and n['safe_exit_verified']and n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'
assert r['operation_code']==r['restore_error']==r['RSC_uncertain']==r['observer_uncertain']==0 and r['restored']==r['safe_release']==r['fixed_registers_unchanged']==r['off_verified']==1
assert t['info_length']==242 and t['header_length_valid']==t['transport_ok']==t['restored']==t['bus_quiescent']==1 and not t['full_IC_info_checksum_verified']and t['identity_ok']==0
assert t['wire_TX']==[0xf1,0,1,0,0x70,255,255,255]+[0]*28 and t['tx_done']==t['rx_done']==36 and t['cancel_sent']==t['abort_sent']==0
assert bytes(t['wire_RX'][8:]).hex()=='f200010112002e27b964010100010000000000000000000000000300'
assert r['transaction_count']==9 and r['pmic_count']==3 and r['client_before']==r['client_after']==[1800,7,0x80000000]and r['client_on']==0x80000001
for tx in r['transactions']:assert tx['operation_code']==tx['restore_error']==0 and tx['restored']==1 and tx['register_write_attempts']==14 and tx['completion']==0x10101
assert [q['pmic_status_raw']for q in r['PMIC']]==[0x43,0xc7,0x43]and t['powered_PMIC']['pmic_status_raw']==0xc7
assert t['pins_before']==t['pins_after']and t['lengths_before']==t['lengths_after']==[0,0]and sp['restored']==en['restored']==1 and sp['clock_before']==sp['clock_after']and sp['pins_before']==sp['pins_after']and en['before']==en['after']and en['DFS_before']==en['DFS_after']
assert en['guards_after'][1]==0x80 and not(en['after'][23]&0x80)
for key in['1','2']:
 q=n['captures'][key];assert q['pmic_status_raw']==0x43 and q['configuration']==[8,7,0,0,7,7,0,0]and q['observer_READ_commands']==5
before=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];after=json.loads(n['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert before==after
assert json.loads(n['jobs']['absent-end']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}and n['jobs']['probe-end']['receipt']['detail']['cpus']==8
replay=j(E/'native-replay.json');assert replay['passed']and replay['events']==1488 and replay['all7_actual_C_cores_and_all_result_bytes']and replay['native_state_sha256']==sha(E/'native-evidence.json')
for name,d in replay['source_sha256'].items():assert sha(X/name)==d
model=j(E/'model.json');assert model['passed']and model['cases']==1660
for name,d in model['source_sha256'].items():assert sha(X/name)==d
build=j(E/'build.json')
for row in build['ARM64_compilation']['objects']:assert sha(X/row['source'])==row['source_sha256']
assert j(E/'source-info.json')['cases']==18 and j(E/'source-binding.json')['cases']==17 and j(E/'IRQ-guard-tests.json')['cases']==387 and j(E/'fixed-guard-tests.json')['cases']==1574 and j(E/'ABI-model.json')['C_response_bytes']==55872
assert j(E/'signature-verification.json')['signed_driver_sha256']==n['driver_sha256']
a.output.write_text(json.dumps({'passed':True,'native_SPI_reads':1,'read_address':'0x10070','payload_bytes':28,'advertised_IC_info_length':242,'complete_block_checksum_verified':False,'new_identity_or_touch_claimed':False,'all_original_configuration_and_off43_verified':True,'temporary_driver_absent_same_session_8CPUs':True,'RSC_transactions_completed_reclaimed':9,'native_core_events_replayed':1488,'masked_M80_not_claimed_cleared':True,'native_commands_submitted_by_audit':0},indent=2)+'\n');print(a.output.read_text())
