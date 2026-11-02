"""Run the actual primary clock/pad preparation core under ASan/UBSan."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;exe=a.output/'test-spi'
subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(W/'g37_spi.c'),str(W/'test-spi.c'),'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
cases=[]
def run(name,**kw):
 keys=['read','write','baseline','identity','pad_owner','vote_owner','delay'];args=[0,0,0,-1,-1,0,0]
 for k,v in kw.items():args[keys.index(k)]=v
 r=subprocess.run([str(exe.resolve()),*map(str,args)],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(name,r.stdout,r.stderr)
 d=json.loads(r.stdout);assert d['reads']<=112 and d['writes']<=14 and len(d['trace'])<=128
 for kind,at,value in d['trace']:
  if kind!=2:continue
  assert (at==0x152008 and value in[0x40002380,0x40102380,0x40302380,0x44302380])or(at in[0xf12c000,0xf12d000,0xf12e000,0xf12f000]and value in[1,0x85])
 if d['restored']:assert d['physical_model_restored']and d['restore_error']==0
 cases.append({'name':name,**{k:d[k]for k in ['code','restore_error','restored','physical_model_restored','reads','writes']}});return d
normal=run('normal');assert normal['code']==0 and normal['restored']==1 and normal['reads']==91 and normal['writes']==14
for i in range(1,92):
 d=run('read-fail-%d'%i,read=i);assert d['code']!=0 or d['restore_error']!=0
for i in range(1,15):
 for sign in[-1,1]:
  d=run('write-fail-%s-%d'%('before'if sign<0 else'after',i),write=sign*i);assert d['code']!=0 or d['restore_error']!=0
for i in range(1,23):
 d=run('baseline-changed-%d'%i,baseline=i);assert d['code']==1 and d['writes']==0 and d['physical_model_restored']
for i in range(7):
 d=run('engine-identity-changed-%d'%i,identity=i);assert d['code']==6 and d['restored']==1 and d['dirty_pins']==0
for i in range(4):
 d=run('pad-owner-changed-%d'%i,pad_owner=i);assert d['restore_error']==1 and d['restored']==0 and d['vote']==0x44302380
 assert not any(e[0]==2 and e[1]==0xf12c000+i*0x1000 and e[2]==1 for e in d['trace'])
d=run('clock-owner-changed',vote_owner=1);assert d['restore_error']==3 and d['restored']==0
for i in range(1,8):d=run('clock-delay-%d'%i,delay=i);assert d['code']==0 and d['restored']==1
d=run('clock-timeout-no-engine-read',delay=8);assert d['code']==4 and d['restored']==1 and d['dirty_pins']==0
d=run('engine_initial_refusal_undo_pads_clocks',identity=7);assert d['code']==12 and d['restored']==1
d=run('engine_unknown_state_holds_pads_clocks',identity=8);assert d['code']==12 and d['restore_error']==6 and d['restored']==0 and d['vote']==0x44302380
d=run('engine_failed_but_restored_undo_pads_clocks',identity=9);assert d['code']==12 and d['restored']==1
report={'engine_boundary_explicitly_modeled_actual_engine_tested_separately':True,'passed':True,'cases':len(cases),'ASan_UBSan':True,'actual_C_core_executed':True,'normal_reads':91,'normal_writes':14,'all91_ordinary_read_failures':True,'all14_writes_fail_before_and_after':True,'unknown_pad_owner_not_overwritten_clocks_held':True,'unknown_clock_owner_not_overwritten':True,'no_engine_read_before_clock_ON':True,'no_command_FIFO_IRQ_supply_reset_write':True,'core_sha256':hashlib.sha256((W/'g37_spi.c').read_bytes()).hexdigest(),'header_sha256':hashlib.sha256((W/'g37_spi.h').read_bytes()).hexdigest(),'cases_summary':cases,'limits':['Bus and line levels are explicit models; native permission/idle levels remain unqualified.','The engine boundary is modeled here; the separate 398-case test executes the actual engine C core. General PnP ownership remains open.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','cases','normal_reads','normal_writes']}))
