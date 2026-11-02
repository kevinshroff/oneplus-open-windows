"""Compile the real observer core with ASan/UBSan and replay fixed bus faults."""
import argparse, hashlib, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
W=Path(__file__).resolve().parent
source=a.inputs/'avdd-G33/independent-PMIC-post.json'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(source)=='b52c14d6a064aa35dd7d870a42e8aff359abd0cfac0372e15b125d4c9a27d6b3'
d=json.loads(source.read_text());words={};golden=[]
for e in d['events']:
 if e['kind']=='mmio_read':words.setdefault(e['address'],e['value']);golden.append([1,e['address'],e['value']])
 elif e['kind']=='observer_read_command':golden.append([2,e['address'],e['command']])
(a.output/'g35_fixture.h').write_text('static const struct{uint32_t at,value;} Initial[]={'+','.join('{0x%x,0x%x}'%(k,v)for k,v in words.items())+'};\n')
exe=a.output/'test-observer'
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),str(W/'g35_observer.c'),str(W/'test-observer.c'),'-o',str(exe.resolve())]
subprocess.run(cmd,check=True,capture_output=True,text=True)
rows=[]
def run(name,want=0,**kw):
 keys=['readfail','writefail','delay','badroute','busy','statuscommand','statusmask','identity','byte','rawstatus']
 v=[0,0,0,-1,-1,-1,0,-1,0,67]
 for key,val in kw.items():v[keys.index(key)]=val
 r=subprocess.run([str(exe.resolve()),*map(str,v)],capture_output=True,text=True)
 assert r.returncode==0 and not r.stderr,(name,r.stdout,r.stderr)
 out=json.loads(r.stdout);assert out['code']==want,(name,out)
 assert out['commands']<=5 and out['writes']<=5 and out['reads']<=120 and out['polls']<=60
 writes=[t for t in out['trace']if t[0]==2]
 allowed=[(0xc440ea0,0x08000007),(0xc441220,0x08000007),(0xc4456e0,0x08000007),(0xc4456e0,0x08000080),(0xc4456e0,0x08000407)]
 assert [(x[1],x[2])for x in writes]==allowed[:len(writes)]
 assert len(writes)==out['writes']
 if want==0:assert out['commands']==out['applied_commands']==out['writes']==5 and out['configuration']==[8,7,0,0,7,7,0,0]
 rows.append({'name':name,'code':out['code'],'stage':out['stage'],'reads':out['reads'],'writes':out['writes'],'polls':out['polls']})
 return out
r=run('exact-native-G33-trace');assert r['trace']==golden
for status in [0,3,0x43,0x87,0xc7]:assert run('raw-status-%02x'%status,rawstatus=status)['status']==status
for delay in range(1,12):assert run('completion-delay-%d'%delay,delay=delay)['polls']==5*(delay+1)
r=run('bounded-timeout-no-reissue',want=6,delay=12);assert r['commands']==r['writes']==r['applied_commands']==1 and r['polls']==12
for index in range(8):run('route-or-arbiter-%d'%index,want=3 if index>=6 else 4,badroute=index)
for index in range(5):
 r=run('pending-no-new-command-%d'%index,want=5,busy=index);assert r['commands']==index
for index in range(5):
 for mask in [2,4,8]:
  r=run('completion-error-%d-%x'%(index,mask),want=7,statuscommand=index,statusmask=mask);assert r['commands']==index+1
for target in range(3):
 for byte in range(8):
  r=run('identity-%d-byte%d'%(target,byte),want=8,identity=target,byte=byte);assert r['commands']==target+1
for index in range(1,37):run('read-failure-%d'%index,want=1,readfail=index)
for index in range(1,6):
 for sign in [-1,1]:
  r=run('write-failure-%s-%d'%('before'if sign<0 else 'after',index),want=1,writefail=sign*index);assert r['commands']==r['writes']==index and r['applied_commands']==index-(sign<0)
report={'passed':True,'cases':len(rows),'ASan_UBSan':True,'actual_C_core_executed':True,'exact_recorded_native_G33_trace_matches':True,'golden_reads':36,'golden_observer_READ_commands':5,'fixed_write_addresses':['0xc440ea0','0xc441220','0xc4456e0'],'all_write_opcodes_EXT_READL':True,'no_reissue_after_failure':True,'all36_normal_read_failures_injected':True,'all5_writes_fail_before_and_after_application':True,'status_byte_preserved_without_interpreting_bit6':True,'source_sha256':sha(W/'g35_observer.c'),'header_sha256':sha(W/'g35_observer.h'),'historical_capture_sha256':sha(source),'cases_summary':rows,'limits':['A bus/fault model does not establish native permission, timing, or MMIO ownership.','Identity checks compare every captured byte, stricter than the historical JS type checks.','No power configuration or supply-vote operation exists in this core.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','cases','exact_recorded_native_G33_trace_matches','ASan_UBSan']}))
