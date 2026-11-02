"""Independent raw-offset audit of the corrected finite G74 OFF-only result."""
from pathlib import Path
import argparse,collections,hashlib,json,struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--previous',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();E=a.evidence
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(name,size):
 b=(E/name).read_bytes();assert len(b)==size;return b
def status(b):
 x=struct.unpack_from('<IIQ8IQQ16s4I',b);assert x[:3]==(96,1,0x31464f343747504f)and x[3:10]==(26100,8,0,576,1,50,0)and x[11]>0 and x[13]==b'G74-off-meta1\0\0\0'
 return {'maps':x[10],'sequence':x[11],'runs':x[14],'observers':x[15],'fault':x[16],'off':x[17]}
def observer(b,at):
 x=struct.unpack_from('<11I',b,at);assert x[0:2]==(0,0)and x[3]==x[5]==5 and 5<=x[4]<=60 and x[2]==31+x[4]and x[6:11]==(1,)*5
 assert b[at+44:at+68]==bytes([32,0,0,2,81,73,1,0,0,4,1,1,4,172,0,0,0,4,1,1,4,171,0,0])
 assert b[at+68:at+80]==bytes([0x43,8,7,0,0,7,7,0,0,0,0,0])
 n=struct.unpack_from('<I',b,at+80)[0];assert n==x[2]+5<=128
 events=list(struct.iter_unpack('<III',b[at+84:at+84+n*12]));assert sum(k==1 for k,ad,v in events)==x[2]
 writes=[(ad,v)for k,ad,v in events if k==2];assert writes==[(0xc440ea0,0x08000007),(0xc441220,0x08000007),(0xc4456e0,0x08000007),(0xc4456e0,0x08000080),(0xc4456e0,0x08000407)]
 assert all(k in(1,2)for k,ad,v in events)and not any(b[at+84+n*12:at+1620])
 return {'status':0x43,'reads':x[2],'writes':5,'polls':x[4],'trace_count':n,'configuration_hex':'0807000007070000'}
before=read('snapshot-before.bin',304);after=read('snapshot-after.bin',304);sb=status(before);sa=status(after)
assert struct.unpack_from('<II',before,96)==struct.unpack_from('<II',after,96)==(50,0)
fixed=struct.unpack_from('<50I',before,104);assert fixed==struct.unpack_from('<50I',after,104)
previous=json.loads((a.previous/'native-evidence.json').read_text());assert list(fixed)==[x['value']for x in previous['snapshot_before']['values']]
raw=read('one-OFF-trial.bin',44728);assert sha(raw)=='40332680f8b32eb91034fbfff0b9d519ed482d1a34edf4137a132eb8b12e50ea'
assert read('frozen-result.bin',44728)==raw
sr=status(raw);assert sr['runs']==1 and sr['observers']==4 and sr['fault']==0 and sr['off']==1
assert struct.unpack_from('<50I',raw,44296)==struct.unpack_from('<50I',raw,44496)==fixed
assert struct.unpack_from('<4I',raw,44696)==(1,1,1,0)
ticks,freq=struct.unpack_from('<QQ',raw,44712);assert ticks==214849 and freq==19200000
core=struct.unpack_from('<41I',raw,104);assert core[:14]==(0,0,1,0,10,3,1,1,1,1,1,0,0,1)
assert core[14:22]==(1800,7,0,1800,7,0,0x80000000,0)
assert core[22:30]==core[30:38]==(1,0,0x201,0,1,0,0xe2,0)and core[38:]==(10,6,10)
addresses=[0x40800,0x40808,0x40804,0x40804,0x40804,0x40804,0x40804,0x40800,0x40808,0x40804]
responses=[1800,7,0,0,0x80000000,0,0,1800,7,0];triggered=[];txns=[];trace_events=0;reads=16;writes=0;derived_waits=0
wa=[0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d2c,0x17a20d24,0x17a20d24,0x17a20d24,0x17a20d24,0x17a20d24,0x17a20d2c,0x17a20d08,0x17a20d34,0x17a20d38,0x17a20d3c]
for i in range(10):
 at=268+i*3264;x=struct.unpack_from('<14I',raw,at);old=struct.unpack_from('<17I',raw,at+56);new=struct.unpack_from('<17I',raw,at+124);msg=0x10108 if i==3 else 0x10008 if i==5 else 0x108
 assert x[:4]==(0,0,1,0)and x[5]==14 and x[6]==x[4]+14<=256 and x[7:10]==(addresses[i],0,msg)and x[11:]==(responses[i],1,1)
 assert x[10]==(0x101 if i==5 else 0x10101)
 assert all(old[j]==new[j]for j in range(17)if j!=12)
 events=list(struct.iter_unpack('<III',raw[at+192:at+192+x[6]*12]));assert all(k in(1,2)for k,ad,v in events)and sum(k==1 for k,ad,v in events)==x[4]
 wv=[msg,addresses[i],0,1,0x10000,0x10000,0x1010000,0x10000,0,0,1,old[8],old[9],old[10]]
 assert [(ad,v)for k,ad,v in events if k==2]==list(zip(wa,wv))
 staged={0x17a20d34:old[8],0x17a20d38:old[9],0x17a20d3c:old[10]};ntriggers=0
 for k,ad,v in events:
  if k==2 and ad in staged:staged[ad]=v
  if k==2 and ad==0x17a20d24 and v==0x1010000:
   assert list(staged.values())==[msg,addresses[i],0];triggered.append({'transaction':i+1,'msgid':msg,'address':addresses[i],'data':0});ntriggers+=1
 assert ntriggers==1 and not any(raw[at+192+x[6]*12:at+3264])
 trigger_at=next(k for k,e in enumerate(events)if e==(2,0x17a20d24,0x1010000))
 reclaim_at=next(k for k in range(trigger_at+1,len(events))if events[k][0:2]==(1,0x17a20000))
 poll_events=events[trigger_at+1:reclaim_at]
 if msg==0x108:
  assert poll_events[-1]==(1,0x17a20d44,x[11]);poll_events=poll_events[:-1]
 assert len(poll_events)%3==0 and 1<=len(poll_events)//3<=24
 for n in range(len(poll_events)//3):
  irq,idle,st=poll_events[n*3:n*3+3];assert irq[:2]==(1,0x17a20d04)and idle[:2]==(1,0x17a20d28)and st[:2]==(1,0x17a20d40)
  accepted=bool(irq[2]&1)and idle[2]==1 and(st[2]==0x101 if msg==0x10008 else st[2]&0x10100==0x10100)
  assert accepted==(n==len(poll_events)//3-1)
 derived_waits+=len(poll_events)//3-1

 if i==5:
  t=next(j for j,e in enumerate(events)if e==(2,0x17a20d24,0x1010000));polls=events[t+1:t+7]
  assert polls==[(k,ad,v)for n in range(2)for k,ad,v in[(1,0x17a20d04,int(n>0)),(1,0x17a20d28,int(n>0)),(1,0x17a20d40,0x101)]]
  noack={'polls':2,'initial_IRQ_and_idle':0,'final_IRQ_and_idle':1,'CMD_status_each_poll':'0x101','response_bit16_each_poll':False,'recorded_completion_field':0x101,'operation_code':0,'original_restored':True}
 reads+=x[4];writes+=x[5];trace_events+=x[6];txns.append({'number':i+1,'address':hex(addresses[i]),'msgid':hex(msg),'response':hex(x[11]),'code':x[0],'restored':x[2],'reads':x[4],'writes':x[5],'trace_count':x[6]})
assert not any(raw[268+10*3264:268+12*3264])
resource=[x for x in triggered if x['msgid']&0x10000];assert [(x['msgid'],x['address'],x['data'])for x in resource]==[(0x10108,0x40804,0),(0x10008,0x40804,0)]
pmics=[]
for i in range(3):
 v=observer(raw,39436+i*1620);pmics.append(v);reads+=v['reads'];writes+=5;trace_events+=v['trace_count']
external=[]
for name,attempt,count in [('pmic-before.bin',1,1),('pmic-after.bin',2,5)]:
 b=read(name,1744);st=status(b);assert st['observers']==count and st['fault']==0 and st['off']==1
 assert struct.unpack_from('<III',b,1716)==(1,attempt,0);external.append(observer(b,96))
assert (reads,writes,trace_events)==(837,155,976)and derived_waits==core[38]
st0=status(read('status-before.bin',96));ready=status(read('ready-before.bin',96));st1=status(read('status-after.bin',96))
assert st0['maps']==st0['runs']==st0['observers']==0 and ready['maps']==22 and ready['runs']==0 and ready['observers']==1 and ready['off']==1
assert st1['maps']==62 and st1['runs']==1 and st1['observers']==5 and st1['off']==1 and st1['fault']==0
j=json.loads((E/'native-evidence.json').read_text());assert j['software_before']==j['software_after']and j['temporary_service_removed']and j['G74_device_absent_after']and j['native_RUNs']==1 and j['diagnostic_qualified']
assert j['protected_partition_hashes_reread']is False and j['physical_touch_used']is False
result={'passed':True,'raw_sha256':sha(raw),'raw_bytes':len(raw),'diagnostic_qualified':True,'core_code':0,'core_restore_error':0,'core_restored':True,'raw_vote_before':0,'raw_vote_after_response_request':hex(core[20]),'raw_vote_after_no_response_request':hex(core[21]),'only_resource_writes':resource,'PMIC_internal':pmics,'PMIC_external':external,'all_50_fixed_words_equal_previous_G72_and_after':True,'noack_completion':noack,'RSC_transactions':txns,'core_reads_including_guards':reads,'core_register_writes':writes,'core_trace_events':trace_events,'waits_1ms':core[38],'elapsed_us':ticks*1000000/freq,'frozen_packet_byte_identical':True,'service_and_device_absent_original_software_exact':True,'fresh_protected_hashes_claimed':False,'limits':['One finite OFF-only test establishes this command/readback correlation, not all SM8550 register semantics.','The no-response command has exact CMD_STATUS101, IRQ-finished and idle1; read/acknowledged commands retain response completion10101.','No global event timestamps, production regulator owner, enable1, SPI/IRQ/DMA or touch qualification is claimed.']}
assert not a.output.exists();a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k]for k in ['passed','diagnostic_qualified','core_code','core_restored','raw_vote_before','raw_vote_after_response_request','raw_vote_after_no_response_request','core_reads_including_guards','core_register_writes','core_trace_events','service_and_device_absent_original_software_exact']}))
