"""Independently decode actual native bytes; offline core replay after one cycle."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
W=Path(__file__).resolve().parent;P=W/'private'
p=argparse.ArgumentParser();p.add_argument('stage',choices=['before','cycle']);a=p.parse_args()
native=json.loads((W/'native-clock.json').read_text())
boot=json.loads((W/'boot-resource.json').read_text())
assert boot['root']['x_is_ramdisk'] and boot['API_DSDT']['bytes']==742
assert native['sessions']['phone']==boot['session']
names=['size','version','magic','build','processors','IRQL','firmware_bytes','firmware_match','firmware_status','prepare_calls','release_calls','D0_entries','D0_exits','in_D0','removed','raw_count','translated_count','resource_OK','mapping_mask','map_calls','unmap_calls']
def decode(path,phase):
 b=path.read_bytes();assert len(b)==1872
 vals=struct.unpack_from('<IIQ18I',b)
 assert len(vals)==len(names)
 out=dict(zip(names,vals));assert vals==(1872,1,0x314b4c433736504f,26100,8,0,742,1,0,1,0,1,0,1,0,3,3,1,7,3,0)
 lists=[]
 for off in [88,148]:
  descriptors=[]
  for i in range(3):
   ty,share,flags,start,length,unused=struct.unpack_from('<BBHQII',b,off+i*20)
   assert ty==3 and share==1 and flags==0 and length==4096 and unused==0
   descriptors.append({'base':start,'length':length,'type':ty,'share':share,'flags':flags})
  assert {d['base']for d in descriptors}=={0x118000,0x123000,0x152000};lists.append(descriptors)
 assert lists[0]==lists[1];out['raw_resources'],out['translated_resources']=lists
 out['cycle_attempts'],reserved=struct.unpack_from('<II',b,208);assert reserved==0
 if phase=='before':
  assert out['cycle_attempts']==0 and not any(b[216:])
 else:
  assert out['cycle_attempts']==1
  cv=struct.unpack_from('<Q10I',b,216)
  clock=dict(zip(['nonce','code','restore_error','restored','phase','reads','writes','waits','trace_count','dirty_mask','active'],cv))
  assert cv[0]==int(native['cycle_nonce'][16:],16)
  assert cv[1:5]==(5,0,1,0) and cv[5:9]==(34,6,1,41) and cv[9:]==(0,0)
  snapshots=[list(struct.unpack_from('<6I',b,off))for off in [264,288,312]]
  baseline=[0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002]
  assert snapshots[0]==snapshots[2]==baseline
  assert snapshots[1]==[0x44302380,0x4000,0,0x100000,0,0x80000002]
  trace=[dict(zip(['kind','register','value','phase'],struct.unpack_from('<4I',b,336+16*i)))for i in range(cv[8])]
  counts={k:sum(e['kind']==k for e in trace)for k in [1,2,3]}
  assert counts=={1:cv[5],2:cv[6],3:cv[7]} and not any(b[336+cv[8]*16:])
  for e in trace:assert e['kind']in(1,2,3) and e['register']<6
  writes=[e for e in trace if e['kind']==2]
  assert [e['register']for e in writes]==[0]*6
  assert [e['value']for e in writes]==[0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380]
  clock.update(before=snapshots[0],enabled=snapshots[1],after=snapshots[2],trace=trace);out['clock']=clock
 out['sha256']=hashlib.sha256(b).hexdigest();return out
before=decode(P/'G67-native-before.bin','before')
if a.stage=='before':
 result={'passed':True,'stage':'before','actual_native_resource_admission_verified':True,'hardware_register_operations':0,'report':before}
else:
 after=decode(P/'G67-native-cycle.bin','cycle')
 replay=subprocess.run([str(P/'replay-native'),str(P/'G67-native-before.bin'),str(P/'G67-native-cycle.bin')],capture_output=True,text=True)
 assert replay.returncode==0,replay.stderr
 replay_result=json.loads(replay.stdout);assert replay_result['policy_accepted']is False
 result={'passed':True,'stage':'cycle','native_finite_clock_cycle_and_restoration_qualified':False,'native_vote_sequence_and_exact_restore_observed':True,'policy_refusal_reproduced_from_native_reads':True,'policy_refusal_code':5,'reason':'Enabled root CMD changed only bit31 from80000000 to0; old source wrongly required the entire idle CMD word unchanged. Core reverted all three votes and all six monitored words.','report_before':before,'report_after':after,'offline_actual_core_replay':replay_result,'sustained_external_clock_lease_or_functional_SPI_qualified':False}
(W/('native-'+a.stage+'-audit.json')).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items()if not k.startswith('report')}),flush=True)
