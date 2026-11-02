"""Offline, independent raw-offset audit of the G72 cold-state refusal.

This makes no phone requests and does not reinterpret refusal as touch success.
"""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
E=a.evidence;J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
s=J(E/'native-evidence.json');b=(E/'power.bin').read_bytes();u=lambda i:struct.unpack_from('<I',b,i)[0];q=lambda i:struct.unpack_from('<Q',b,i)[0]
assert len(b)==959896 and u(0)==80 and u(4)==1 and q(8)==0x314f52463935474f
assert u(16)==26100 and u(20)==8 and u(24)==0 and u(28)==576 and u(32)==1
assert [u(i)for i in [80,84,88,92,96,100]]==[3,0,1,2,3,1]
assert [u(i)for i in [104,108,112,116,120,124,128]]==[0,0,0,0,1,0,0]
assert [u(i)for i in [136,140,144]]==[1800,7,0]
assert u(959860)==0 and u(959864)==u(959868)==u(959872)==1
assert q(959888)==19200000
tx=[]
for i,(address,response)in enumerate([(0x40800,1800),(0x40808,7),(0x40804,0)]):
 at=164+i*3264
 assert u(at)==u(at+4)==0 and u(at+8)==1
 assert u(at+28)==address and u(at+32)==0 and u(at+36)==0x108 and u(at+44)==response and u(at+48)==1
 assert u(at+20)==14 and u(at+24)<=256
 before=list(struct.unpack_from('<17I',b,at+56));after=list(struct.unpack_from('<17I',b,at+124))
 assert all(x==y for j,(x,y)in enumerate(zip(before,after))if j!=12)
 assert after[12]==response
 # A query stages MSGID0x108. Reclaim later restores the pre-existing MSGID;
 # correlate each trigger with the staged command instead of treating every
 # restored MSGID word as an executed command. RPMh addresses are payloads.
 events=[struct.unpack_from('<III',b,at+192+j*12)for j in range(u(at+24))]
 assert sum(k==2 for k,addr,val in events)==14
 assert all(addr not in [0xc7b7000,0xc7b7008,0xb000000]for k,addr,val in events)
 command_writes=[v for k,addr,v in events if k==2 and addr==0x17a20d34]
 assert command_writes==[0x108,before[8]]
 active={0x17a20d34:before[8],0x17a20d38:before[9],0x17a20d3c:before[10]};triggers=0
 for kind,addr,value in events:
  if kind!=2:continue
  if addr in active:active[addr]=value
  if addr==0x17a20d24 and value==0x1010000:
   assert [active[x]for x in [0x17a20d34,0x17a20d38,0x17a20d3c]]==[0x108,address,0];triggers+=1
 assert triggers==1
 tx.append({'address':hex(address),'response':response,'query_opcode':hex(u(at+36)),'register_writes':u(at+20),'controller_fields_restored':True,'only_read_query_triggered':True})
assert b[29540+68]==0x43 and b[29540+69:29540+77]==bytes([8,7,0,0,7,7,0,0])
assert b[34400:34432]==b[34432:34464]
# Entire downstream SPI/GENI/touch result is the zero-initialized, unentered
# result. This is different from an executed component reporting restoration.
assert not any(b[34472:959860])
assert s['phase']=='original_software_baseline_restored_capture_preserved'
assert s['cold_regulator_baseline_refusal_verified']and not s['physical_touch_qualified']
assert s['raw_sha256']==sha(E/'power.bin')
assert len(s['fixed50_comparison'])==50 and all(x['before']==x['after']for x in s['fixed50_comparison'])
for key in ['pmic_before','pmic_after']:
 v=s[key];assert v['operation_code']==0 and v['pmic_status_raw']==0x43 and v['configuration']==[8,7,0,0,7,7,0,0] and v['fixed_registers_unchanged']==1
for key in ['source_before','source_after']:
 v=s[key];assert v['firmware_match']==v['D0']==v['started']==1 and v['processors']==8 and v['reports_submitted']==v['reports_accepted']==v['accepted_mask']==0
owner=s['session_after'];assert owner['state']==3 and owner['outcome']==3 and owner['starts']==owner['hardware_calls']==owner['result_ready']==owner['thread_joined']==1 and owner['poll_cycles']==0
assert s['source_after']['live_error']==3 and s['source_after']['live_attempts']==1
v=s['audit_after'];assert v['owned_roots']==0 and not v['source_interfaces'] and not v['source_service']['present'] and not v['inbox_include']['present'] and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
assert all(s['baseline'][k]==v['inventory'][k]for k in ['files','services','DSDT_sha256'])
ready=J(E/'ready.json');done=J(E/'done.json');qual=J(E/'qualification.json');child=json.loads(done['admin']['Output'])
assert ready['Token']==done['token']==s['token'] and ready['Foreground']and ready['DPIAware']and qual['owned_foreground_verified']and qual['DPI_aware']
assert done['window_closed']and done['events']==done['dropped']==0 and not(E/'events.jsonl').read_bytes()
assert done['admin']['ExitCode']==1 and not child['ok']and child['error']=='full session did not complete; inspect saved evidence'
assert child['result']['sha256']==sha(E/'power.bin')and child['result']['driver_session']==owner
assert s['window_receipt']['status']=='error'and s['window_receipt']['id']==s['jobs']['single-powered-window']['id']
assert len([k for k in s['jobs']if k=='single-powered-window'])==1
assert s['max_powered_invocations']==1 and s['created']['created']and not s['roots_removed']['owned_roots']
assert s['tree_ready']['tree'][0]['id'].casefold()==s['created']['instance'].casefold()
assert len(s['tree_ready']['tree'])==3 and all(s['jobs'][k]['status']=='ok'for k in ['remove-root','remove-TLC','remove-VHF','delete-unused-child-package','delete-source-service','uninstall-root','audit-after','probe-after'])
package=J(E/'source-package.json')
assert package['files']['OpenG59.sys']=='dd0699a33c5b04b36b6df3957cf3f6c83b77f9844c1391eed165fff9f272dc74'
power=(a.source/'g59_power.c').read_text();assert 'ClientBefore[2]!=0x80000000u' in power and 'bit31 semantics are established' in power
result={'passed':True,'audit_native_operations':0,'raw_capture_bytes':len(b),'raw_sha256':sha(E/'power.bin'),'native_launch_jobs':1,'power_operation_code':3,'power_stage':2,'cold_client_before':[1800,7,0],'required_qualified_profile':[1800,7,0x80000000],'enable_attempted':False,'SPI_GENI_touch_not_entered':True,'native_poll_cycles':0,'Windows_pointer_events':0,'worker_joined':True,'controller_queries':tx,'fixed50_exact':True,'independent_before_after_PMIC_off43':True,'all_owned_nodes_packages_service_removed':True,'original_files_services_DSDT_and_8CPUs':True,'physical_held_contact_qualified':False,'source_kernel_unchanged':'G59','source_power_sha256':sha(a.source/'g59_power.c'),'limits':['No contact data was captured. The cue preceded confirmation of native startup; an executing job is insufficient evidence of an armed touch controller.','Cold raw-enable0 versus80000000 remains unresolved. No enable/off normalization or guard relaxation was performed.','Fresh protected-partition hashes were not reread: no raw partition, boot, BCD, firmware or reboot operation was submitted in this experiment.','The audit proves consistency of retained raw data, source and receipts; it is not a new native trial.']}
a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
