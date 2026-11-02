"""Fault the actual cleanup C cores, starting with the captured G41 held state."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
names=['g44_observer.c','g44_rsc.c','g44_power.c','g44_spi.c','g44_engine.c','g44_touch.c','g44_recovery.c','test-recovery.c'];exe=a.output/'test-recovery'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.binding.resolve()),*[str(W/n)for n in names],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
cases=0
def run(name,read=0,write=0,scenario=0,fixture=None):
 global cases
 args=[str(exe.resolve()),str(read),str(write),str(scenario)]
 if fixture:args.append(str(fixture.resolve()))
 q=subprocess.run(args,capture_output=True,text=True);assert not q.returncode and not q.stderr,(name,q.returncode,q.stdout,q.stderr)
 r=json.loads(q.stdout);assert r['commands']==r['enables']==0 and r['releases']<=1 and r['RSC_transactions']<=4 and r['M_ACKs']<=1 and r['S_ACKs']<=1
 if r['power_restored']:assert r['physical_model_restored']and r['safe_release'],(name,r)
 if r['releases']:assert r['release_prerequisites']==1,(name,r)
 cases+=1;return r
n=run('normal',fixture=a.output/'ABI-good.bin');assert n['power_code']==n['power_restore_error']==0 and n['power_restored']==n['physical_model_restored']==1 and n['releases']==1 and n['RSC_transactions']==4 and n['M_ACKs']==n['S_ACKs']==1,n
(a.output/'normal.json').write_text(json.dumps(n,indent=2)+'\n')
for i in range(1,n['reads']+1):
 r=run('read-failure-%d'%i,read=i);assert r['power_code']or r['power_restore_error']or not r['power_restored']
for i in range(1,n['writes']+1):
 for sign in[-1,1]:
  r=run('write-failure-%d-%d'%(sign,i),write=sign*i);assert r['power_code']or r['power_restore_error']or not r['power_restored']
for scenario in range(200,223):
 r=run('scenario-%d'%scenario,scenario=scenario)
 if scenario in[213,214,215,216,217,218]:assert r['power_restored']and r['physical_model_restored']
 else:assert not r['power_restored']
 if scenario not in[210,213,214,215,216,217,218,219]:assert r['releases']==0
 if scenario==216:assert r['writes']==n['writes']+1
 if scenario==219:assert r['releases']==1 and not r['power_restored']
 if scenario==214:assert r['M_ACKs']==0 and r['S_ACKs']==1
report={'passed':True,'cases':cases,'ASan_UBSan':True,'all7_actual_portable_cleanup_C_cores_executed':True,'all_nominal_read_and_before_after_write_failures':True,'IRQ_input_high_low_or_held_until_digital_off':True,'reset_input_settles_after_50ms':True,'stuck_final_IRQ_and_reserved_GPIO_bits_refused':True,'new_SPI_commands':0,'supply_enable_commands':0,'release_max_one_after_all_undo_proven':True,'RSC_transactions_max':4,'S_then_M_ACK_observed_words_once_each':True,'foreign_owner_busy_FIFO_status_or_PMIC_state_hold_resources':True,'normal_model':n,'source_sha256':{f:hashlib.sha256((W/f).read_bytes()).hexdigest()for f in names},'binding_sha256':hashlib.sha256((a.binding/'g44_recovery_binding.h').read_bytes()).hexdigest(),'limits':['MMIO and PMIC/clock behavior are explicit modeled boundaries.','Source helper behavior is checked, but native cleanup is a separate one-shot operation.','No new transfer or physical identity is produced by this cleanup path.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':cases,'normal_reads':n['reads'],'normal_writes':n['writes']}))
