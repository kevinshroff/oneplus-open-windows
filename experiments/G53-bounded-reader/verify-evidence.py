"""Offline proof of the native guard stop and restoration; never claim reader success."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G53';X=R/'experiments/G53-bounded-reader';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');r=n['trial'];t=r['touch'];q=t['poll'];sp=r['spi'];en=sp['engine']
assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and n['safe_exit_verified']and n['outcome']=='bounded_reader_stopped_with_clean_baseline'
assert r['operation_code']==6 and t['operation_code']==18 and q['operation_code']==4 and q['cycles']==1
assert r['restore_error']==t['restore_error']==0 and r['restored']==r['safe_release']==r['fixed_registers_unchanged']==r['off_verified']==1
assert t['command_attempted']==5 and t['cancel_sent']==t['abort_sent']==0 and q['clear_attempts']==q['clear_completed']==0
assert q['wire_count']==q['read_attempts']==1 and q['bus_quiescent']==1
f=q['records'][0];assert f['kind']==0 and f['error']==4 and f['header_valid']==1 and f['body_checked']==1 and f['body_valid']==0 and f['point_count']==0 and f['contact_mask']==0 and not f['contacts']
b=bytes(f['raw_bytes'][:26]);assert b==(E/'native-zero-contact26.bin').read_bytes()==bytes.fromhex('8003000000038600ffff00000000000000000000000000000000')
assert b==bytes(t['post_report']['wire_RX'][8:34])and sum(b[:6])==int.from_bytes(b[6:8],'little')==134 and int.from_bytes(b[8:10],'little')==65535
w=q['wires'][0];assert w['kind']==1 and w['address']=='0x10274'and w['payload']==26 and w['transport_ok']==1 and w['tx_done']==w['rx_done']==34
commands=[e['value']for e in t['trace']if e['kind']==2 and e['address']=='0xa90600'];assert commands==[0x18000000,0x18000000,0x08000000,0x18000000,0x18000000]
assert t['ack']['wire_TX']==[0xf0,0,1,2,0x74,0]+[0]*30 and t['ack']['tx_done']==6 and t['ack']['rx_done']==0
assert t['pins_before']==t['pins_after']and t['lengths_before']==t['lengths_after']==[0,0]and t['restored']==t['bus_quiescent']==1
assert sp['restored']==en['restored']==1 and sp['clock_before']==sp['clock_after']and sp['pins_before']==sp['pins_after']and en['before']==en['after']and en['DFS_before']==en['DFS_after']
assert r['transaction_count']==9 and r['client_before']==r['client_after']==[1800,7,0x80000000]
for tx in r['transactions']:assert tx['operation_code']==tx['restore_error']==0 and tx['restored']==1 and tx['register_write_attempts']==14
assert [v['pmic_status_raw']for v in r['PMIC']]==[0x43,0xc7,0x43]and t['powered_PMIC']['pmic_status_raw']==0xc7
for v in n['captures'].values():assert v['pmic_status_raw']==0x43 and v['configuration']==[8,7,0,0,7,7,0,0]
a1=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];a2=json.loads(n['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert a1==a2 and len(a2)==50
assert n['jobs']['bounded-poll-trial']['receipt']['status']=='error'and n['jobs']['bounded-poll-trial']['receipt']['exit_code']==1
assert json.loads(n['jobs']['absent-end']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}and n['jobs']['probe-end']['receipt']['detail']['cpus']==8
for name,cases in [('model.json',12384),('adapter-policy.json',1635),('poll-model.json',108),('ABI-model.json',18),('stock-decoder-model.json',6204)]:
 v=j(E/name);assert v['passed']and v['cases']==cases
 if isinstance(v.get('source_sha256'),dict):
  for f,d in v['source_sha256'].items():assert sha(X/f)==d
assert j(E/'adapter-policy.json')['adapter_sha256']==sha(X/'g53_driver.c')and j(E/'ABI-model.json')['source_sha256']==sha(X/'g53_client.go')
build=j(E/'build.json');assert len(build['ARM64_compilation']['objects'])==12
for row in build['ARM64_compilation']['objects']:assert sha(X/row['source'])==row['source_sha256']
for f,d in build['ARM64_compilation']['headers'].items():assert sha(X/f)==d
assert sha(X/'g53_client.go')==build['Go_client']['source_sha256']and n['client_sha256']==build['Go_client']['output_sha256']
assert n['driver_sha256']==j(E/'signature-verification.json')['signed_driver_sha256']
repro=j(E/'source-object-reproduction.json');assert repro['all12_normalized_ARM64_objects_identical']and repro['Go_ARM64_client_byte_identical']
z=j(E/'zero-source.json');assert z['passed']and z['stock_zero_count_releases_before_point_access']and z['G53_guard_stop_reproduced']and z['packet_sha256']==sha(E/'native-zero-contact26.bin')and z['G53_decoder_sha256']==sha(X/'g53_report.c')
out={'passed':True,'native_reader_completed':False,'native_guard_stop_verified':True,'reason':'valid zero-count touch header with unparsed FFFF trailing bytes fails the current body-checksum rule','packet_hex':b.hex(),'poll_event_clears':0,'initial_event_clear':1,'SPI_commands':5,'all_original_hardware_baselines_restored_and_driver_absent':True,'same_boot_8CPUs':True,'native_commands_submitted_by_audit':0};a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
