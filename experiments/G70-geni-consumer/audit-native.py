"""Independent byte decoder and actual-core replay, never another hardware cycle."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
W=Path(__file__).resolve().parent;P=W/'private';p=argparse.ArgumentParser();p.add_argument('stage',choices=['before','cycle']);a=p.parse_args();native=json.loads((W/'native-clock.json').read_text());boot=json.loads((W/'boot-resource.json').read_text());assert boot['root']['x_is_ramdisk'] and boot['API_DSDT']['bytes']==768 and native['sessions']['phone']==boot['session']
keys=['size','version','magic','build','processors','IRQL','firmware_bytes','firmware_match','firmware_status','prepare_calls','release_calls','D0_entries','D0_exits','in_D0','removed','raw_count','translated_count','resource_OK','mapping_mask','map_calls','unmap_calls']
def decode(path,phase):
 b=path.read_bytes();assert len(b)==2056;v=struct.unpack_from('<IIQ18I',b);assert v==(2056,1,0x314e45473037504f,26100,8,0,768,1,0,1,0,1,0,1,0,5,5,1,15,4,0);r=dict(zip(keys,v));lists=[]
 for side,off in enumerate([88,188]):
  rows=[];mem={};irq=[]
  for i in range(5):
   q=b[off+20*i:off+20*(i+1)];ty,share,flags=struct.unpack_from('<BBH',q);assert share==1 and not flags
   if ty==3:
    start,n,res=struct.unpack_from('<QII',q,4);assert not res and start not in mem;mem[start]=n;rows.append({'type':3,'base':start,'length':n,'raw_hex':q.hex()})
   else:
    assert ty==2;level,group,vector,affinity=struct.unpack_from('<HHIQ',q,4);irq.append((level,group,vector,affinity));rows.append({'type':2,'level':level,'group':group,'vector':vector,'affinity':affinity,'raw_hex':q.hex()})
  assert mem=={0x118000:4096,0x123000:4096,0x152000:4096,0xa90000:16384} and len(irq)==1
  if side==0:assert irq[0]==(389,0,389,0xffffffff)
  else:assert irq[0][2] and irq[0][3]
  lists.append(rows)
 r['raw_resources'],r['translated_resources']=lists;r['cycle_attempts'],reserved=struct.unpack_from('<II',b,288);assert not reserved
 if phase=='before':assert r['cycle_attempts']==0 and not any(b[296:])
 else:
  assert r['cycle_attempts']==1;c=struct.unpack_from('<Q10I',b,296);clock=dict(zip(['nonce','code','restore_error','restored','phase','reads','writes','waits','trace_count','dirty_mask','active'],c));assert c[0]==int(native['cycle_nonce'][16:],16) and c[1:5]==(0,0,1,0) and c[5]==35+2*c[7] and c[6]==6 and c[7]<=14 and c[8]==41+3*c[7] and c[9:]==(0,0)
  baseline=[0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002];snaps=[list(struct.unpack_from('<6I',b,o))for o in [344,368,392]];assert snaps[0]==snaps[2]==baseline and snaps[1]==[0x44302380,0x4000,0,0x100000,0,0x80000002]
  trace=[dict(zip(['kind','register','value','phase'],struct.unpack_from('<4I',b,416+16*i)))for i in range(c[8])];assert not any(b[416+16*c[8]:1952]);assert {k:sum(e['kind']==k for e in trace)for k in [1,2,3]}=={1:c[5],2:6,3:c[7]}
  assert all(e['kind']in(1,2,3) and e['register']<6 for e in trace);writes=[e for e in trace if e['kind']==2];assert [e['register'] for e in writes]==[0]*6 and [e['value']for e in writes]==[0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380]
  clock.update(before=snaps[0],enabled=snaps[1],after=snaps[2],trace=trace);r['clock']=clock
  pr=struct.unpack_from('<26I',b,1952);expected=(0,0,0x102,0x102,0x20102864,0x20104800,0,0,0,0);assert pr[:6]==(0,20,2,1,1,0) and pr[6:16]==pr[16:]==expected;r['probe']={'code':0,'reads':20,'completed_passes':2,'identity_match':True,'stable':True,'first':list(pr[6:16]),'second':list(pr[16:]),'offsets':[0x40,0x64,0x68,0x6c,0xe24,0xe28,0x610,0x640,0x800,0x804]}
 r['sha256']=hashlib.sha256(b).hexdigest();return r
before=decode(P/'G70-native-before.bin','before')
if a.stage=='before':result={'passed':True,'stage':'before','actual_native_resource_admission_verified':True,'hardware_register_operations':0,'report':before}
else:
 after=decode(P/'G70-native-cycle.bin','cycle');q=subprocess.run([str(P/'replay-native'),str(P/'G70-native-before.bin'),str(P/'G70-native-cycle.bin')],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);replay=json.loads(q.stdout);assert replay['policy_accepted'];result={'passed':True,'stage':'cycle','native_finite_clock_cycle_and_restoration_qualified':True,'native_bounded_GENI_identity_consumer_qualified':True,'report_before':before,'report_after':after,'offline_actual_core_replay':replay,'engine_writes':0,'IRQ_delivery_DMA_pinmux_supplies_or_functional_SPI_qualified':False}
(W/('native-'+a.stage+'-audit.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if not k.startswith('report')}))
