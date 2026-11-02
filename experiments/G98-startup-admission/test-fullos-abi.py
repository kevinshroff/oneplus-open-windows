from pathlib import Path
import argparse,json,struct,subprocess,hashlib
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--fixtures',type=Path,default=W/'private/integration-model-01');a=p.parse_args();O=a.output;O.mkdir();exe=O/'decoder';subprocess.run(['go','build','-o',str(exe.resolve()),str(W/'g98_hwdecode.go'),str(W/'decode-native.go')],check=True)
cases=0
for f in sorted((a.fixtures).glob('*.bin')):
 q=subprocess.run([str(exe.resolve()),str(f.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr;r=json.loads(q.stdout);b=f.read_bytes();U=lambda at:struct.unpack_from('<I',b,at)[0];t=r['touch'];poll=t['poll'];expected=json.loads((a.fixtures/'tests.json').read_text())['results'];d=next(x for x in expected if x['label']==f.stem)
 assert len(b)==969808 and r['operation_code']==d['power_code']==0 and r['restored']==d['power_restored']==1 and r['powered_hook_called']==1 and r['safe_release']==1
 assert r['transaction_count']==12 and r['pmic_count']==3 and r['client_before']==r['client_after']==[1800,7,0] and r['client_on']==0x80000001
 assert [x['pmic_status_raw']for x in r['PMIC']]==[3,0x87,3]
 assert t['operation_code']==d['touch_code']==0 and poll['cycles']==d['poll_cycles'] and poll['wire_count']==d['poll_wire_count']
 assert t['trace_capacity']==65536
 n=U(51480);first=max(0,n-65536);assert t['trace_total']==n and t['trace_first_index']==first and len(t['trace'])==min(n,65536)
 for i,row in zip(range(first,n),t['trace']):
  at=52272+(i%65536)*12;assert row['index']==i and (row['kind'],int(row['address'],16),row['value'])==struct.unpack_from('<III',b,at)
 limit=d['limit'];assert poll['limit']==limit and len(poll['records'])==min(limit,100)
 for i,row in zip(range(max(0,limit-100),limit),poll['records']):
  at=840972+(i%100)*504;assert row['cycle']==i+1 and row['raw_bytes']==list(b[at+122:at+212])
 n=U(891372);first=max(0,n-400);assert len(poll['wires'])==min(n,400)
 for i,row in zip(range(first,n),poll['wires']):
  at=891376+(i%400)*196;assert row['index']==i and row['wire_RX']==list(b[at+124:at+196])
 cases+=1
b=(a.fixtures/'idle.bin').read_bytes()
for name,at,v in [('limit',840916,300001),('magic',8,0),('tx',136,13),('pmic',140,4),('touchtrace',51480,350000001),('spi',44412,129),('engine',46260,385),('cycles',840920,9),('wires',891372,33),('retrykind',841060,3),('settle',840788,7),('poweredPmic',838784,129)]:
 x=bytearray(b);struct.pack_into('<I',x,at,v);f=O/(name+'.bin');f.write_bytes(x);q=subprocess.run([str(exe.resolve()),str(f.resolve())],capture_output=True,text=True);assert q.returncode!=0,name;cases+=1
# Build a PMIC response from the actual C observer ABI; the native run also
# carries this exact observer layout. Guard fields and chronological events
# must not be shifted by the unrelated RSC transaction layout.
b=(a.fixtures/'idle.bin').read_bytes();pm=b[:80]+b[39528:41148]+struct.pack('<IIIQQ',1,1,0,1234,19200000)
assert len(pm)==1728
f=O/'PMIC-C-ABI.bin';f.write_bytes(pm);q=subprocess.run([str(exe.resolve()),'--pmic',str(f.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr;v=json.loads(q.stdout);n=struct.unpack_from('<I',pm,160)[0];assert len(v['trace'])==n
for i,row in enumerate(v['trace']):assert (row['kind'],int(row['address'],16),row['value'])==struct.unpack_from('<III',pm,164+i*12)
cases+=1
out={'passed':True,'cases':cases,'production_Go_decoder_and_actual_C_ABI':True,'all_three_rings_validated_at_8_401_2500_3000_cycles':True,'native_operations':0};(O/'tests.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
