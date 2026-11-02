#!/usr/bin/env python3
"""Bind native receipt chain, actual raw snapshot and independent Go decode."""
from pathlib import Path
import hashlib,json,struct
w=Path(__file__).resolve().parent;p=w/'private';load=lambda n:json.loads((p/n).read_text());sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
boot=load('fresh-boot-intent.json');assert boot['phase']=='temporary_boot_command_accepted'
session=load('native-session.json')['session'];assert session!=boot['previous_phone_session']
v=load('owner-final-native.json');s=v['snapshot'];independent=load('owner-final-offline.json');assert s==independent
raw=(p/'owner-final-raw.bin').read_bytes();assert len(raw)==128344 and hashlib.sha256(raw).hexdigest()==v['sha256']==load('final-snapshot-get-receipt.json')['sha256']
for n in ['final-snapshot-receipt.json','final-snapshot-get-receipt.json','repeat-10-receipt.json','repeat-22-receipt.json','owner-load-receipt.json']:
 r=load(n);assert r['status']=='ok'and r.get('exit_code',0)==0 and r['session']==session,n
assert s['last_command_id']==35 and s['LastResult']==1 and s['Running']==1 and s['MapsLive']==2 and not s['NativeFault']and not s['SafeToUnload']
state=s['state'];assert state['Phase']==3 and state['BatchesCompleted']==state['BatchesStarted']==34 and not state['BatchActive']and not state['Pending']and state['Query']==10
for n in ['Fault','TransportUncertain','RpcUncertain','CloseSent','CloseAcked','RemoteClosed']:assert state[n]==0,n
assert state['CurrentOffers']==16 and state['NextLocalId']==359 and state['IgnoredOpens']==8
assert s['last_batch']['wire_valid_mask']==s['last_batch']['value_valid_mask']==1023 and not s['last_batch']['service_rejected_mask']
before=load('owner-idle-native.json')['snapshot'];assert before['last_command_id']==13 and before['state']['BatchesCompleted']==12 and before['cookie']==s['cookie']
assert state['OwnTx']<before['state']['OwnTx']and state['OwnRx']<before['state']['OwnRx'],'Both ring indices must wrap without reset'
assert s['FinalDescriptor'][:4]==[state['OwnTx'],state['OwnTx'],state['OwnRx'],state['OwnRx']]and not any(s['FinalDescriptor'][4:])
ports=[]
for i in range(32):
 at=240+1336+144*i;present,cid,n,signals=struct.unpack_from('<4I',raw,at)
 if present:assert 1<=n<=128;ports.append({'cid':cid,'name':raw[at+16:at+16+n].rstrip(b'\0').decode('ascii'),'signals':signals})
assert len(ports)==8 and all(r['cid']!=state['RemoteCid']for r in ports)
trace=[]
for i in range(32):
 at=240+60776+2104*i;serial,when,batch=struct.unpack_from('<3Q',raw,at);direction,cmd,cid,param,n,tx,rx,query=struct.unpack_from('<8I',raw,at+24)
 if not serial:continue
 assert direction in [1,2]and 8<=n<=2048 and not n&7
 frame=raw[at+56:at+56+n];assert struct.unpack_from('<HHI',frame)==(cmd,cid,param)
 if direction==1 and cmd==9:
  assert cid==1 and n in [32,40]and struct.unpack_from('<II',frame,16)==(0x800a,1)
  opcode=struct.unpack_from('<I',frame,24)[0];assert opcode in [0,1,0x30,0x32]and opcode!=0x31
 trace.append({'serial':serial,'time_us':when,'batch':batch,'direction':direction,'command':cmd,'cid':cid,'parameter':param,'bytes':n,'query':query})
trace.sort(key=lambda r:r['serial']);assert len(trace)==32 and trace[-1]['serial']+1==state['TraceNext']and all(a['serial']+1==b['serial']for a,b in zip(trace,trace[1:]))
profile=s['last_batch']['raw_values'];assert profile['VoltageMax']==8900000
report=load('fresh-DSP-report-native.json');assert report['ok']and report['report']['stable_double_read']and report['report']['phase']==[3,3]and report['report']['PAS_sequence_accepted']
start=load('owner-start-native.json')['snapshot'];initial=load('owner-initial-native.json')['snapshot'];assert initial['map_calls']==0 and initial['Attempted']==0
result={'native_authority':True,'session':session,'predecessor_session':boot['previous_phone_session'],'software_fastboot_cycle_observed':True,'firmware_boot_accepted':True,'same_G155_image':boot['image_sha256'],'fresh_OADP_sha256':sha(p/'fresh-OADP.bin'),'fresh_OSER_sha256':sha(p/'fresh-OSER.bin'),'fresh_firmware_reports_validated':True,'capture_sha256':v['sha256'],'independent_Go_decode_matches_native':True,'native_owner_loads':1,'native_batches_completed':34,'native_queries_completed':340,'native_frame_totals':{'TX':state['TxFrames'],'RX':state['RxFrames']},'both_16KiB_FIFO_indices_wrapped_without_reset':True,'recycled_local_intent_next_id':state['NextLocalId'],'remote_charger_cid':state['RemoteCid'],'unbound_ports_retained':ports,'rolling_trace_frames_verified':trace,'timer_calls':s['timer_calls'],'elapsed_owner_us':s['now_us']-start['now_us'],'owner_retained_live':True,'native_close_and_unload_qualified':False,'raw_profile':profile,'charger_setters':0,'partition_flashes':0,'same_boot_PAS_retries':0,'production_power_lease_qualified':False,'physical_charging_qualified':False,'limits':['Native read-only bring-up owner remains live in WinPE; it is not a production PnP/power driver.','No physical USB unplug, full OS lifetime, sleep/wake or native close/unload tested here.','Eight advertised endpoints are retained metadata, not working peripheral drivers.','Voltage-max8900000 is the first live cached property8 reading; units/topology and live setter path remain unqualified. Do not equate it with the SCPQ per-cell readback or copy it into a setter.','Other generic voltage/SOC/current/temperature still show the previously identified defaults.','Local batch generation is not a firmware transaction ID; no retry follows ambiguous RPC/transport failure.']}
(p/'native-analysis.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k not in ['rolling_trace_frames_verified','unbound_ports_retained','limits']},indent=2))
