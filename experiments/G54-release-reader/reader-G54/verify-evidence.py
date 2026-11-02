"""Offline audit of native bounded reading, zero-count semantics and restoration."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[3]);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();R=a.repository;E=R/'evidence/G54';X=R/'experiments/G54-release-reader';Y=X/'reader-G54';j=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
n=j(E/'native-evidence.json');r=n['trial'];t=r['touch'];q=t['poll'];sp=r['spi'];en=sp['engine']
assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and n['safe_exit_verified']
assert n['outcome']in['completed8cycle_reader_with_points','completed8cycle_reader_without_points']
assert r['operation_code']==t['operation_code']==q['operation_code']==0 and q['cycles']==8
assert r['restore_error']==t['restore_error']==0 and r['restored']==r['safe_release']==r['fixed_registers_unchanged']==r['off_verified']==1
assert t['cancel_sent']==t['abort_sent']==0 and 12<=t['command_attempted']<=28
assert q['bus_quiescent']==1 and q['elapsed_us']<=250000 and q['clear_attempts']==q['clear_completed']<=8
assert q['read_attempts']==8+q['tail_reads']and q['wire_count']==q['read_attempts']+q['clear_attempts']
assert t['command_attempted']==4+q['wire_count']
releases=points=idle=requests=0
for f in q['records']:
 b=bytes(f['raw_bytes']);assert len(b)==90 and f['read_bytes']in[26,34,42,50,58,66,74,82,90]
 if f['kind']==1:assert b[0]==0 and f['clear_attempted']==0;idle+=1;continue
 assert f['header_checked']==f['header_valid']==1 and(sum(b[:6])&65535)==int.from_bytes(b[6:8],'little')
 assert f['clear_attempted']==f['clear_completed']==1
 if f['kind']==2:assert b[0]==0x40 and b[2]==0;requests+=1;continue
 assert f['kind']==3 and f['flags']&0x80 and f['flags']&~0x8b==0
 count=b[2]&15;assert f['point_count']==count<=10
 if not count:
  assert f['body_checked']==f['body_valid']==0 and f['meaningful_bytes']==8 and f['contact_mask']==0 and f['point_type']==0 and f['contacts']==[]
  releases+=1;continue
 needed=8+count*8+2;assert f['meaningful_bytes']==needed and f['body_checked']==f['body_valid']==1
 assert(sum(b[8:needed-2])&65535)==int.from_bytes(b[needed-2:needed],'little')
 ids=set()
 for at,c in enumerate(f['contacts']):
  z=b[8+at*8:16+at*8];ident=z[0]>>4;assert ident<10 and ident not in ids;ids.add(ident)
  assert c['Id']==ident and c['Type']==z[0]&15 and c['X']==int.from_bytes(z[2:4],'little')and c['Y']==int.from_bytes(z[4:6],'little')
 assert f['contact_mask']==sum(1<<v for v in ids)and len(ids)==count;points+=1
assert len(q['records'])==8 and q['idle_records']==idle and q['request_records']==requests and q['contact_records']==points+releases
clears=[]
for f in q['wires']:
 assert f['transport_ok']==1 and f['cancel_sent']==f['abort_sent']==0
 if f['kind']==3:
  assert f['address']=='0x10274'and f['payload']==1 and f['tx_done']==6 and f['rx_done']==0
  assert f['wire_TX']==[0xf0,0,1,2,0x74,0]+[0]*66;clears.append(f)
 else:
  assert f['kind']in[1,2]and f['address']==('0x10274'if f['kind']==1 else'0x1028e')
  assert f['tx_done']==f['rx_done']==f['payload']+8
assert len(clears)==q['clear_completed']
commands=[e['value']for e in t['trace']if e['kind']==2 and e['address']=='0xa90600'];assert len(commands)==t['command_attempted']and commands.count(0x08000000)==1+len(clears)
assert t['ack']['wire_TX']==[0xf0,0,1,2,0x74,0]+[0]*30 and t['ack']['tx_done']==6 and t['ack']['rx_done']==0
assert t['pins_before']==t['pins_after']and t['lengths_before']==t['lengths_after']and t['restored']==t['bus_quiescent']==1
assert sp['restored']==en['restored']==1 and sp['clock_before']==sp['clock_after']and sp['pins_before']==sp['pins_after']and en['before']==en['after']and en['DFS_before']==en['DFS_after']
assert r['transaction_count']==9 and r['client_before']==r['client_after']==[1800,7,0x80000000]
for tx in r['transactions']:assert tx['operation_code']==tx['restore_error']==0 and tx['restored']==1 and tx['register_write_attempts']==14
assert [v['pmic_status_raw']for v in r['PMIC']]==[0x43,0xc7,0x43]and t['powered_PMIC']['pmic_status_raw']==0xc7
for v in n['captures'].values():assert v['pmic_status_raw']==0x43 and v['configuration']==[8,7,0,0,7,7,0,0]
a1=json.loads(n['jobs']['snapshot-before']['receipt']['output'])['result']['values'];a2=json.loads(n['jobs']['snapshot-after']['receipt']['output'])['result']['values'];assert a1==a2 and len(a2)==50
assert n['jobs']['bounded-poll-trial']['receipt']['status']=='ok'and n['jobs']['bounded-poll-trial']['receipt']['exit_code']==0
assert json.loads(n['jobs']['absent-end']['receipt']['output'])['result']=={'device_absent':True,'service_absent':True}and n['jobs']['probe-end']['receipt']['detail']['cpus']==8
for name,cases in [('model.json',15687),('adapter-policy.json',1896),('poll-model.json',108),('ABI-model.json',19),('stock-decoder-model.json',71804)]:
 v=j(E/name);assert v['passed']
 if cases is not None:assert v['cases']==cases
 if isinstance(v.get('source_sha256'),dict):
  for f,d in v['source_sha256'].items():assert sha(Y/f)==d
assert j(E/'model.json')['cases']>12384 and set(j(E/'model.json')['tested_profile_statistics'])=={'mixed','max','release'}
assert j(E/'adapter-policy.json')['adapter_sha256']==sha(Y/'g54_driver.c')and j(E/'ABI-model.json')['source_sha256']==sha(Y/'g54_client.go')
build=j(E/'build.json');assert len(build['ARM64_compilation']['objects'])==12
for row in build['ARM64_compilation']['objects']:assert sha(Y/row['source'])==row['source_sha256']
for f,d in build['ARM64_compilation']['headers'].items():assert sha(Y/f)==d
assert build['ARM64_compilation']['binding_sha256']==j(E/'adapter-policy.json')['binding_sha256']==sha(Y/'bindings/g54_binding.h')
assert sha(Y/'g54_client.go')==build['Go_client']['source_sha256']and n['client_sha256']==build['Go_client']['output_sha256']
assert n['driver_sha256']==j(E/'signature-verification.json')['signed_driver_sha256']
assert n['jobs']['hash-driver']['receipt']['sha256']==n['driver_sha256']and n['jobs']['hash-client']['receipt']['sha256']==n['client_sha256']
delta=j(E/'delta-audit.json');assert delta['passed']and set(delta['changed_files_hunks'])=={'g54_contract.c','g54_report.c'}
for f,d in delta['new_sha256'].items():assert sha(Y/f.replace('private/inputs/','bindings/'))==d
for f,d in delta['old_sha256'].items():assert sha(R/'experiments/G53-bounded-reader'/f.replace('private/inputs/','bindings/'))==d
repro=j(E/'source-object-reproduction.json');assert repro['all12_normalized_ARM64_objects_identical']and repro['Go_ARM64_client_byte_identical']
lc=j(E/'lifecycle-model.json');assert lc['passed']and lc['cases']==1048598
for f,d in lc['source_sha256'].items():assert sha(X/f)==d
out={'passed':True,'native_reader_completed':True,'cycles':8,'zero_count_release_records':releases,'point_records':points,'idle_records':idle,'request_records':requests,'polled_event_clears':len(clears),'initial_event_clear':1,'SPI_commands':len(commands),'elapsed_poll_us':q['elapsed_us'],'zero_count_trailing_body_not_parsed_or_claimed':True,'all_original_hardware_baselines_restored_and_driver_absent':True,'same_boot_8CPUs':True,'live_HID_or_continuous_touch_qualified':False,'native_commands_submitted_by_audit':0};a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
