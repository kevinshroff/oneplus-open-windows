"""Execute actual RSC/power/observer C with fault injection and historical writes."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;exe=a.output/'test-power'
subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',*[str(W/x)for x in['g38_rsc.c','g38_power.c','g38_observer.c','test-power.c']],'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
cases=[]
def run(name,mode=2,read=0,write=0,scenario=0,delay=0):
 r=subprocess.run([str(exe.resolve()),*map(str,[mode,read,write,scenario,delay])],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(name,r.stdout,r.stderr)
 d=json.loads(r.stdout);assert d['enables']<=1 and d['releases']<=1 and d['transactions']<=9 and d['writes']<=141
 if d['restored']and mode==2:assert d['physical_model_restored']and not d['restore_error']
 cases.append({'name':name,**{k:d[k]for k in['code','restore_error','restored','enabled','enables','releases']}});return d
n=run('normal');assert n['code']==0 and n['restored']==n['on_verified']==n['off_verified']==1 and n['enables']==n['releases']==1 and n['transactions']==9 and n['writes']==141
historical=a.inputs/'avdd-G33/trial/native-result.json';h=json.loads(historical.read_text());expected=[(e['address'],e['value'])for e in h['events']if e['kind']=='write_attempt'and 0x17a20000<=e['address']<0x17a22000];assert len(expected)==126 and list(map(tuple,n['RSC_writes']))==expected
for i in range(1,n['reads']+1):
 d=run('power_read_fail_%d'%i,read=i);assert d['code']or d['restore_error']or not d['restored']
for i in range(1,n['writes']+1):
 for sign in[-1,1]:
  d=run('power_write_fail_%d_%d'%(sign,i),write=sign*i);assert d['code']or d['restore_error']or not d['restored']
for i in range(8):
 d=run('power_pin_guard_%d'%i,scenario=20+i);assert d['code']==1 and d['writes']==0
for scenario in[1,2,3,4,5,6,7]:
 d=run('power_fault_%d'%scenario,scenario=scenario);assert d['code']or d['restore_error']
 if scenario in[1,2]:assert d['rsc_uncertain']and d['enables']==0
 if scenario==3:assert d['off_verified']and d['physical_model_restored']
 if scenario==4:assert d['restore_error']==5 and not d['restored']
 if scenario==6:assert d['rsc_uncertain']and d['releases']==0 and not d['restored']
 if scenario==7:assert d['rsc_uncertain']and d['enabled']==1 and d['releases']==0 and not d['restored']
for delay in[1,4,23]:
 d=run('completion_delay_%d'%delay,delay=delay);assert d['code']==0 and d['restored']
for mode in[0,1]:
 d=run('single_transaction_%d'%mode,mode=mode);assert d['code']==0 and d['restored']
report={'passed':True,'actual_C_cores_executed':['g38_rsc.c','g38_power.c','g38_observer.c'],'ASan_UBSan':True,'cases':len(cases),'normal_model_reads':n['reads'],'normal_model_writes':n['writes'],'all_nominal_reads_and_before_after_writes_faulted':True,'all126_RSC_writes_identical_to_G33_native_recording':True,'historical_native_result_sha256':hashlib.sha256(historical.read_bytes()).hexdigest(),'whole_raw_on_off_status_c7_43_required':True,'no_reset_AVDD_GPIO_SPI_clock_GIC_or_direct_SPMI_RW_write':True,'max_enable_and_release_one_each':True,'old_WRITE_payload_not_restored_before_idle_disabled':True,'conflicting_owner_not_overwritten':True,'source_sha256':{n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in['g38_rsc.c','g38_power.c','g38_observer.c','g38_power.h']},'case_summary':cases,'limits':['MMIO, asynchronous completion and physical rails are explicit models; native execution is a separate qualification.','The raw PMIC bit6 name remains unknown; full status bytes are retained.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in['passed','cases','normal_model_reads','normal_model_writes']}))
