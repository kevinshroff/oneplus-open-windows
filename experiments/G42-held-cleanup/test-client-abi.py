"""Execute unchanged Go response decoders on the actual C model ABI fixture."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;source=(W/'g42_client.go').read_text()
def function(name):
 m=re.search(r'^func '+name+r'\(',source,re.M);assert m,name;start=m.start();cur=source.index('{',m.end());depth=1;cur+=1
 # Selected functions have no literal braces in strings/comments.
 while depth:
  if source[cur]=='{':depth+=1
  elif source[cur]=='}':depth-=1
  cur+=1
 return source[start:cur]
status=re.search(r'type Status struct \{.*?\n\}',source,re.S).group()
body='package main\nimport("encoding/binary";"encoding/json";"errors";"fmt";"os";"strings")\nconst magic uint64=0x314f52463234474f\nconst ioctlPower uintptr=0x22600c\nconst registerCount=50\nvar fixture []byte\n'+status+'\nfunc request()[]byte{return nil}\nfunc ioctl(h,code uintptr,b []byte,n int)([]byte,uint32,error){return fixture,uint32(len(fixture)),nil}\n'
for name in['parseStatus','checkStatus','capturePower']:body+=function(name)+'\n'
body+='func main(){var e error;fixture,e=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};r,e:=capturePower(0);if e!=nil{json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":false,"error":e.Error()});return};json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":true,"result":r})}\n'
(a.output/'decoder.go').write_text(body);exe=a.output/'decoder';subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(exe.resolve()),str((a.output/'decoder.go').resolve())],check=True,capture_output=True,text=True)
b=a.fixture.read_bytes();assert len(b)==55864;cases=[]
def run(name,data):
 f=a.output/(name+'.bin');f.write_bytes(data);q=subprocess.run([str(exe.resolve()),str(f.resolve())],check=True,capture_output=True,text=True);assert not q.stderr;v=json.loads(q.stdout);cases.append({'case':name,'ok':v['ok']});return v
v=run('C_model_recovery',b);assert v['ok'];r=v['result'];t=r['touch'];assert r['powered_hook_called']==0 and r['safe_release']==r['restored']==r['restored_fixed_baseline']==1
assert r['transaction_count']==4 and r['pmic_count']==1 and r['enable_attempted']==0 and r['release_attempted']==1
assert t['transport_ok']==t['identity_ok']==t['command_attempted']==t['tx_done']==t['rx_done']==0 and t['restored']==1
assert t['patch_PID']==t['ROM_PID']==''and t['wire_TX']==t['wire_RX']==[0]*36
assert t['powered_PMIC']['pmic_status_raw']==0xc7 and r['PMIC'][0]['pmic_status_raw']==0x43
assert r['client_before']==r['client_after']==[1800,7,0x80000000]and r['client_on']==0x80000001
assert t['pins_on'][0]==0x281 and t['pins_on'][4]==0x2c0 and t['pins_on'][8]==0xc0
assert t['command_history']==[0x18000000,0x18000000]and not any(e['kind']==2 and e['address']in['0xa90600','0xa90604','0xa90700']for e in t['trace'])
assert r['spi']['engine']['restored']==r['spi']['restored']==1 and len(t['trace'])==t['register_reads']+t['register_write_attempts']
for name,at,value in[('magic',8,0),('Power_tx_count',96,5),('Power_pmic_count',100,2),('SPI_trace',34496,129),('engine_trace',36344,385),('touch_trace',41564,1025),('powered_pmic_trace',54292,129)]:
 data=bytearray(b);struct.pack_into('<I',data,at,value);assert not run(name,data)['ok']
assert not run('short',b[:-1])['ok'];assert not run('long',b+b'\0')['ok']
denied=bytearray(len(b));denied[:80]=b[:80];struct.pack_into('<I',denied,80,1002);v=run('lifetime_denial',denied);assert v['ok']and v['result']['operation_code']==1002 and v['result']['transaction_count']==v['result']['pmic_count']==v['result']['touch']['command_attempted']==v['result']['powered_hook_called']==0
report={'passed':True,'cases':len(cases),'original_Go_functions_executed_unchanged':['parseStatus','checkStatus','capturePower'],'source_sha256':hashlib.sha256((W/'g42_client.go').read_bytes()).hexdigest(),'C_fixture_sha256':hashlib.sha256(b).hexdigest(),'C_response_bytes':len(b),'all_recovery_component_counts_arrays_and_nested_observer_offsets_checked':True,'no_new_SPI_frame_or_identity_claimed':True,'guard_denial_keys_present_correctly_typed':True,'case_results':cases,'limits':['The fixture is modeled held-state cleanup; it issues no new transfer or identity query. No phone or Windows kernel is accessed.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases),'C_response_bytes':len(b)}))
