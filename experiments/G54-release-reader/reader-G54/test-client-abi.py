"""Execute unchanged Go response decoders on the actual C model ABI fixture."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;source=(W/'g54_client.go').read_text()
def function(name):
 m=re.search(r'^func '+name+r'\(',source,re.M);assert m,name;start=m.start();cur=source.index('{',m.end());depth=1;cur+=1
 # Selected functions have no literal braces in strings/comments.
 while depth:
  if source[cur]=='{':depth+=1
  elif source[cur]=='}':depth-=1
  cur+=1
 return source[start:cur]
status=re.search(r'type Status struct \{.*?\n\}',source,re.S).group()
body='package main\nimport("encoding/binary";"encoding/json";"errors";"fmt";"os";"strings")\nconst magic uint64=0x314f52463435474f\nconst ioctlPower uintptr=0x22600c\nconst registerCount=50\nvar fixture []byte\n'+status+'\nfunc request()[]byte{return nil}\nfunc ioctl(h,code uintptr,b []byte,n int)([]byte,uint32,error){return fixture,uint32(len(fixture)),nil}\n'
for name in['parseStatus','checkStatus','capturePower']:body+=function(name)+'\n'
body+='func main(){var e error;fixture,e=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};r,e:=capturePower(0);if e!=nil{json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":false,"error":e.Error()});return};json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":true,"result":r})}\n'
(a.output/'decoder.go').write_text(body);exe=a.output/'decoder';subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(exe.resolve()),str((a.output/'decoder.go').resolve())],check=True,capture_output=True,text=True)
b=a.fixture.read_bytes();assert len(b)==150888;cases=[]
def run(name,data):
 f=a.output/(name+'.bin');f.write_bytes(data);q=subprocess.run([str(exe.resolve()),str(f.resolve())],check=True,capture_output=True,text=True);assert not q.stderr;v=json.loads(q.stdout);cases.append({'case':name,'ok':v['ok']});return v
v=run('C_model_success',b);assert v['ok'];r=v['result'];t=r['touch'];assert r['powered_hook_called']==r['safe_release']==r['restored']==r['fixed_registers_unchanged']==1
assert t['transport_ok']==t['restored']==t['header_length_valid']==1 and t['tx_done']==t['rx_done']==250 and t['identity_ok']==0 and t['info_length']==242 and t['full_IC_info_checksum_verified']and t['ROM_PID']==t['patch_PID']==''
rep=t['report'];assert rep['transport_ok']==rep['contract_verified']==rep['header_present']==rep['header_checksum_valid']==1 and rep['body_complete']==rep['body_checksum_valid']==0 and rep['attempted']==1 and rep['tx_done']==rep['rx_done']==34 and rep['point_count']==0 and rep['event_flags']==64
ack=t['ack'];post=t['post_report'];assert ack['attempted']==ack['transport_ok']==ack['contract_verified']==post['attempted']==post['transport_ok']==post['contract_verified']==1
assert ack['tx_done']==6 and ack['rx_done']==0 and ack['wire_TX']==[0xf0,0,1,2,0x74,0]+[0]*30 and not any(ack['wire_RX'])
assert post['tx_done']==post['rx_done']==34 and not post['header_present']and not post['header_checksum_valid']and not post['body_complete']and not post['body_checksum_valid']
assert post['wire_TX']==[0xf1,0,1,2,0x74,255,255,255]+[0]*28 and t['IRQ_sample_mask']==3 and t['IRQ_before']==[0,0]and t['IRQ_after']==[1,0]
assert rep['wire_TX']==[0xf1,0,1,2,0x74,255,255,255]+[0]*28
assert t['settle_sample_count']==6 and len(t['settle_samples'])==6
assert [x['elapsed_us']for x in t['settle_samples']]==[0,10000,20000,30000,40000,50000]
assert [x['input']for x in t['settle_samples']]==[0,0,0,0,1,1]
assert all(x['control']==0xc0 and x['IRQ_config']==0xe2 and x['IRQ_status']==0 for x in t['settle_samples'])
assert t['pins_on'][0]==0x281 and t['pins_on'][4]==0x2c0 and t['pins_on'][8]==0xc0
assert t['powered_PMIC']['pmic_status_raw']==0xc7 and t['wire_TX']==[0xf1,0,1,0,0x70,255,255,255]+[0]*244
assert r['spi']['engine']['bus_hz']==960000 and r['spi']['engine']['restored']==1 and r['client_before']==r['client_after']==[1800,7,0x80000000]
assert len(t['trace'])==t['register_reads']+t['register_write_attempts']
for name,at,value in[('magic',8,0),('Power_tx_count',96,10),('Power_pmic_count',100,4),('SPI_trace',34496,129),('engine_trace',36344,385),('touch_trace',41564,8193),('powered_pmic_trace',140740,129),('settle_count',142744,7)]:
 data=bytearray(b);struct.pack_into('<I',data,at,value);assert not run(name,data)['ok']
assert not run('short',b[:-1])['ok'];assert not run('long',b+b'\0')['ok']
denied=bytearray(len(b));denied[:80]=b[:80];struct.pack_into('<I',denied,80,1002);v=run('lifetime_denial',denied);assert v['ok']and v['result']['operation_code']==1002 and v['result']['transaction_count']==v['result']['pmic_count']==v['result']['touch']['command_attempted']==v['result']['powered_hook_called']==0
for label,expected in [('mixed',{'cycles':8,'read_attempts':9,'tail_reads':1,'clear_completed':6,'contact_records':5,'request_records':1,'idle_records':2,'wire_count':15}),('max',{'cycles':8,'read_attempts':16,'tail_reads':8,'clear_completed':8,'contact_records':8,'request_records':0,'idle_records':0,'wire_count':24})]:
 other=a.fixture.parent/('ABI-'+label+'.bin');v=run('C_model_'+label,other.read_bytes());assert v['ok'];q=v['result']['touch']['poll'];assert q['operation_code']==0
 for key,value in expected.items():assert q[key]==value,(label,key,q[key],value)
 assert len(q['records'])==8 and len(q['wires'])==expected['wire_count']
 if label=='mixed':assert [r['kind']for r in q['records']]==[3,3,3,1,3,3,2,1]and [r['point_count']for r in q['records']]==[1,1,0,0,2,10,0,0]
 if label=='max':assert all(r['read_bytes']==90 and r['tail_read']==1 and len(r['contacts'])==10 and r['body_valid']==1 for r in q['records'])
v=run('C_model_native_release',(a.fixture.parent/'ABI-release.bin').read_bytes());assert v['ok'];q=v['result']['touch']['poll'];assert q['operation_code']==0 and q['cycles']==8 and q['clear_completed']==1 and q['idle_records']==7 and q['wire_count']==9
r=q['records'][0];assert r['kind']==3 and r['point_count']==0 and r['meaningful_bytes']==8 and r['header_valid']==1 and r['body_checked']==r['body_valid']==0 and r['point_type']==0 and r['contacts']==[] and r['raw_bytes'][8:10]==[255,255]
for name,at,value in [('cycles',142872,9),('wires',146144,25),('rawbytes',142912,91)]:
 data=bytearray(b);struct.pack_into('<I',data,at,value);assert not run(name,data)['ok']
data=bytearray(b);struct.pack_into('<I',data,143024,3);struct.pack_into('<I',data,143036,11);assert not run('contact_count',data)['ok']
report={'passed':True,'cases':len(cases),'original_Go_functions_executed_unchanged':['parseStatus','checkStatus','capturePower'],'source_sha256':hashlib.sha256((W/'g54_client.go').read_bytes()).hexdigest(),'C_fixture_sha256':hashlib.sha256(b).hexdigest(),'C_response_bytes':len(b),'all_component_counts_header_fields_and_nested_observer_offsets_checked':True,'guard_denial_keys_present_correctly_typed':True,'case_results':cases,'limits':['The fixture and peer identity are synthetic. No phone or Windows kernel is accessed.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases),'C_response_bytes':len(b)}))
