"""Run the actual guarded configuration core with independent MMIO fault models."""
import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;exe=a.output/'test-engine'
subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(W/'g37_engine.c'),str(W/'test-engine.c'),'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
cases=[]
def run(name,**kw):
 keys=['read','write','guard','owner','clock','delay','index0'];args=[0,0,-1,-1,0,0,0]
 for k,v in kw.items():args[keys.index(k)]=v
 r=subprocess.run([str(exe.resolve()),*map(str,args)],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(name,r.stdout,r.stderr)
 d=json.loads(r.stdout);assert d['reads']<=320 and d['writes']<=48 and len(d['trace'])<=384
 if d['restored']:assert d['model_restored']and d['restore_error']==0
 assert not any(e[0]==2 and (e[1]&0xfff)in[0x600,0x604,0x618,0x620,0x700,0x780]for e in d['trace'])
 cases.append({'name':name,**{k:d[k]for k in ['code','restore_error','restored','model_restored','reads','writes']}});return d
n=run('normal_DFS_index1_to_XO_index0');assert n['code']==0 and n['restored']and n['bus_hz']==960000 and n['writes']==48
for i in range(1,n['reads']+1):
 d=run('read_fail_%d'%i,read=i);assert d['code']or d['restore_error']
for i in range(1,n['writes']+1):
 for sign in[-1,1]:
  d=run('write_%d_%d'%(sign,i),write=sign*i);assert d['code']or d['restore_error']
for i in range(10):
 d=run('quiet_guard_changed_%d'%i,guard=i);assert d['code']==1 and d['writes']==0
for i in range(24):
 d=run('restore_owner_changed_%d'%i,owner=i);assert d['restore_error']==3 and not d['restored']
for mode in[1,3,4,5,6]:
 d=run('clock_refusal_%d'%mode,clock=mode);assert d['code']==2 and d['writes']==0
for mode in[2,7,8]:
 d=run('source_qualified_clock_%d'%mode,clock=mode);assert d['code']==0 and d['restored']
for delay in range(1,8):
 d=run('DFS_level_delay_%d'%delay,delay=delay);assert d['code']==0 and d['restored']
d=run('DFS_level_timeout',delay=9);assert d['code']==6 and d['restored']
d=run('index_already_XO',index0=1);assert d['code']==0 and d['restored']and d['writes']==46
report={'passed':True,'cases':len(cases),'ASan_UBSan':True,'actual_C_core_executed':True,'normal_reads':n['reads'],'normal_writes':n['writes'],'all_ordinary_reads_faulted':True,'all_writes_faulted_before_and_after':True,'unknown_engine_owner_not_overwritten':True,'all_10_quiet_guards_refuse_before_writes':True,'clock_source0_mode0_HID0_or1_required':True,'no_SPI_command_FIFO_IRQ_clear_power_or_GPIO_write':True,'core_sha256':hashlib.sha256((W/'g37_engine.c').read_bytes()).hexdigest(),'header_sha256':hashlib.sha256((W/'g37_engine.h').read_bytes()).hexdigest(),'case_summaries':cases,'limits':['MMIO effects, clock switching and line levels here are explicit models, not physical bus evidence.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','cases','normal_reads','normal_writes']}))
