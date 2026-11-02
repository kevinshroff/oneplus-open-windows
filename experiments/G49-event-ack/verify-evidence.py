"""Offline audit of G49's fresh IC-info, report prefetch and restored native state."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2])
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G49';X=R/'experiments/G49-event-ack'
j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');r=n['trial'];t=r['touch'];sp=r['spi'];en=sp['engine'];rep=t['report']
assert n['outcome']=='event_flag_cleared'and n['safe_exit_verified']and n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'
assert r['operation_code']==r['restore_error']==r['RSC_uncertain']==r['observer_uncertain']==0
assert r['restored']==r['safe_release']==r['fixed_registers_unchanged']==r['off_verified']==1
assert t['info_length']==242 and t['header_length_valid']==t['transport_ok']==t['restored']==t['bus_quiescent']==1
assert t['full_IC_info_checksum_verified']and t['identity_ok']==0 and t['command_attempted']==4
assert t['wire_TX']==[0xf1,0,1,0,0x70,255,255,255]+[0]*244
assert t['tx_done']==t['rx_done']==250 and t['cancel_sent']==t['abort_sent']==0
data=bytes(t['wire_RX'][8:250]);assert data==(E/'IC-info-242.bin').read_bytes()
assert len(data)==242 and(sum(data[:-2])&65535)==int.from_bytes(data[-2:],'little')==6850
assert rep['attempted']==rep['transport_ok']==rep['contract_verified']==rep['header_present']==rep['header_checksum_valid']==1
assert rep['body_complete']==rep['body_checksum_valid']==0 and rep['event_flags']==0x40 and rep['point_count']==0
assert rep['tx_done']==rep['rx_done']==34 and rep['cancel_sent']==rep['abort_sent']==0
assert rep['wire_TX']==[0xf1,0,1,2,0x74,255,255,255]+[0]*28
report=bytes(rep['wire_RX'][8:34]);assert report==(E/'report-prefetch-26.bin').read_bytes()
assert report[:8]==bytes.fromhex('4001000000034400')and report[2]==0
assert sum(report[:6])==int.from_bytes(report[6:8],'little')==68
commands=[x for x in t['trace']if x['kind']==2 and x['address']=='0xa90600']
assert [x['value']for x in commands]==[0x18000000,0x18000000,0x08000000,0x18000000]
sacks=[x for x in t['trace']if x['kind']==2 and x['address']=='0xa90648']
assert len(sacks)==3 and all(x['value']==0xc000000 for x in sacks)
ack=t['ack'];post=t['post_header']
assert ack['attempted']==ack['transport_ok']==ack['contract_verified']==post['attempted']==post['transport_ok']==post['contract_verified']==1
assert ack['tx_done']==6 and ack['rx_done']==0 and ack['state']==4 and ack['cancel_sent']==ack['abort_sent']==0
assert ack['wire_TX']==[0xf0,0,1,2,0x74,0]+[0]*30 and not any(ack['wire_RX'])
assert post['tx_done']==post['rx_done']==16 and post['cancel_sent']==post['abort_sent']==0
assert post['wire_TX']==[0xf1,0,1,2,0x74,255,255,255]+[0]*28
post_header=bytes(post['wire_RX'][8:16]);assert post_header==(E/'post-header-8.bin').read_bytes()==b'\0'+report[1:8]
assert post['header_present']==post['header_checksum_valid']==post['body_complete']==post['body_checksum_valid']==post['event_flags']==0
assert t['IRQ_sample_mask']==3 and t['IRQ_before']==t['IRQ_after']==[0,0]
assert data==(R/'evidence/G48/IC-info-242.bin').read_bytes()and report==(R/'evidence/G48/report-prefetch-26.bin').read_bytes()
assert r['transaction_count']==9 and r['pmic_count']==3 and r['client_before']==r['client_after']==[1800,7,0x80000000]and r['client_on']==0x80000001
for tx in r['transactions']:
 assert tx['operation_code']==tx['restore_error']==0 and tx['restored']==1 and tx['register_write_attempts']==14 and tx['completion']==0x10101
assert [q['pmic_status_raw']for q in r['PMIC']]==[0x43,0xc7,0x43]and t['powered_PMIC']['pmic_status_raw']==0xc7
assert t['pins_before']==t['pins_after']and t['lengths_before']==t['lengths_after']==[0,0]
assert sp['restored']==en['restored']==1 and sp['clock_before']==sp['clock_after']and sp['pins_before']==sp['pins_after']and en['before']==en['after']and en['DFS_before']==en['DFS_after']
assert en['guards_after'][1]==0x80 and not(en['after'][23]&0x80)
for key in['1','2']:
 q=n['captures'][key];assert q['pmic_status_raw']==0x43 and q['configuration']==[8,7,0,0,7,7,0,0]and q['observer_READ_commands']==5
before=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values']
after=json.loads(n['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert before==after
assert json.loads(n['jobs']['absent-end']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}
assert n['jobs']['probe-end']['receipt']['detail']['cpus']==8
replay=j(E/'native-replay.json')
assert replay['passed']and replay['events']==2072 and replay['all8_actual_C_cores_and_all_result_bytes']and replay['native_state_sha256']==sha(E/'native-evidence.json')
for name,d in replay['source_sha256'].items():assert sha(X/name)==d
for filename,cases in[('model.json',2202),('contract-tests.json',2905)]:
 q=j(E/filename);assert q['passed']and q['cases']==cases
 for name,d in q['source_sha256'].items():assert sha(X/name)==d
build=j(E/'build.json');assert len(build['ARM64_compilation']['objects'])==9
for row in build['ARM64_compilation']['objects']:assert sha(X/row['source'])==row['source_sha256']
for name,d in build['ARM64_compilation']['headers'].items():assert sha(X/name)==d
assert sha(X/'g49_client.go')==build['Go_client']['source_sha256']
for name,count in[('source-info.json',27),('source-binding.json',17),('source-irq.json',9),('IRQ-guard-tests.json',387),('fixed-guard-tests.json',1574),('ABI-model.json',11),('checksum-source.json',5822),('adapter-policy.json',192),('event-source.json',262)]:
 q=j(E/name);assert q['passed']and q['cases']==count
assert j(E/'ABI-model.json')['C_response_bytes']==69048
assert j(E/'event-source.json')['captured_report_sha256']==sha(E/'report-prefetch-26.bin')
assert j(E/'signature-verification.json')['signed_driver_sha256']==n['driver_sha256']
assert j(E/'source-object-reproduction.json')['all9_normalized_ARM64_objects_identical']and j(E/'source-object-reproduction.json')['Go_ARM64_client_byte_identical']
a.output.write_text(json.dumps({'passed':True,'native_SPI_reads':3,'native_event_acknowledgements':1,'event_ack_frame_hex':'f00001027400','event_ack_TX_bytes':6,'event_ack_RX_bytes':0,'fresh_IC_info_bytes':242,'fresh_IC_info_checksum':6850,'fresh_IC_info_matches_source_decoded_G48':True,'prefetch_event_flags':'0x40','request_byte':0,'post_header_hex':post_header.hex(),'only_event_flag_byte_changed':True,'idle_header_checksum_not_claimed_valid':True,'powered_IRQ_before':t['IRQ_before'],'powered_IRQ_immediate_after':t['IRQ_after'],'IRQ_deassertion_or_working_input_claimed':False,'all_original_configuration_and_off43_verified':True,'temporary_driver_absent_same_session_8CPUs':True,'RSC_transactions_completed_reclaimed':9,'native_core_events_replayed':2072,'masked_M80_not_claimed_cleared':True,'native_commands_submitted_by_audit':0},indent=2)+'\n')
print(a.output.read_text())
