"""Execute the full eight-core path at modeled MMIO/peer boundaries with faults."""
from pathlib import Path
import argparse,hashlib,json,subprocess,os
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
native=a.inputs/'engine-G37/native-qualification.json';e=json.loads(native.read_text())['spi']['engine']
off=[0xe1c,0xe18,0x28,0x24,0x224,0x230,0x22c,0x250,0x24c,0x254,0x258,0x25c,0x260,0x264,0x268,0x278,0x284,0x288,0x7c,0x48,0x80c,0x810,0x814,0x614]
text='static const uint32_t ConfigOffsets[24]={'+','.join(hex(v)for v in off)+'};\n'
for n,values in [('NativeConfig',e['before']),('NativeDfs',e['DFS_before'])]:text+='static const uint32_t '+n+'[]={'+','.join(hex(v)for v in values)+'};\n'
(a.output/'native-model-input.h').write_text(text)
ic=a.inputs/'info-G47/private/IC-info-242.bin';ic=ic if ic.exists()else a.inputs/'info-G47/IC-info-242.bin';assert hashlib.sha256(ic.read_bytes()).hexdigest()=='1ffa9ab8f7a0794ca0d3e2f38958a3c9db1022c458110bb735e400dcbd482780';(a.output/'native-model-input.h').write_text(text+'static const uint8_t ModelIc[242]={'+','.join(map(str,ic.read_bytes()))+'};\n')
exe=a.output/'test-trial';names=['g56_observer.c','g56_rsc.c','g56_power.c','g56_spi.c','g56_engine.c','g56_touch.c','g56_contract.c','g56_plan.c','g56_report.c','g56_poll.c','geni_fifo.c','g56_input.c','g56hid_lifecycle.c','test-trial.c']
initial_sha={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names+['g56_touch.h','g56_contract.h','g56_trial.h','g56_poll.h','g56_report.h']}
compiled=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),*[str(W/n)for n in names],'-o',str(exe.resolve())],capture_output=True,text=True);assert compiled.returncode==0,compiled.stderr
child=subprocess.Popen([str(exe.resolve()),'--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
count=0;codes={}
def run(name,read=0,write=0,scenario=0,barrier=0,fixture=None,limit=8):
 global count
 child.stdin.write(' '.join(map(str,[limit,read,write,scenario,barrier]))+' '+(str(fixture.resolve())if fixture else'-')+'\n');child.stdin.flush();line=child.stdout.readline()
 assert line,(name,child.poll(),child.stderr.read())
 d=json.loads(line);assert d['commands']<=4+3*limit and d['event_writes']<=1+limit and d['enables']<=1 and d['releases']<=1 and d['cancels']<=1 and d['aborts']<=1 and d['accepted_mask']==0
 if d['power_restored']:assert d['physical_model_restored'],(name,d)
 count+=1;k=str(d['power_code'])+'/'+str(d['power_restore_error']);codes[k]=codes.get(k,0)+1;return d
n=run('normal',fixture=a.output/'ABI-good.bin');assert n['power_code']==n['spi_code']==n['touch_code']==0 and n['power_restored']==n['transport_ok']==n['header_length_valid']==1 and n['identity_ok']==0 and n['info_length']==242 and n['full_checksum_valid']==1 and n['commands']==12 and n['report_transport']==n['report_contract']==n['report_header']==1 and n['report_body_complete']==n['report_body']==0 and n['report_TX_done']==n['report_RX_done']==34 and n['TX_done']==n['RX_done']==250
assert n['ack_transport']==n['post_transport']==n['event_writes']==1 and n['ack_TX']==6 and n['ack_RX']==0 and n['post_TX']==n['post_RX']==34 and n['IRQ_samples']==3 and n['IRQ_before']==0 and n['IRQ_after']==1 and not n['post_header_present']
assert n['settle_count']==6 and n['settle_last_us']==50000 and n['settle_inputs']==[0,0,0,0,1,1]
assert n['wire_TX']==[0xf1,0,1,0,0x70,0xff,0xff,0xff]+[0]*244
for i in range(1,n['reads']+1):
 d=run('read_failure_%d'%i,read=i);assert d['power_code']or d['power_restore_error']or not d['power_restored']
for i in range(1,n['writes']+1):
 for sign in[-1,1]:
  d=run('write_failure_%d_%d'%(sign,i),write=sign*i);assert d['power_code']or d['power_restore_error']or not d['power_restored']
for i in range(1,n['barriers']+1):
 d=run('barrier_failure_%d'%i,barrier=i);assert d['power_code']or d['power_restore_error']or not d['power_restored']
for scenario in[1,2,3,4,5,6,7,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,200,201,202,203,204,205,206,207,208,209,210,301,302,303,305,306,401,402,403,404,405,406]:
 d=run('scenario_%d'%scenario,scenario=scenario)
 if scenario==100:assert d['transport_ok']and not d['full_checksum_valid']and d['power_restored']
 elif scenario in[101,102]:assert d['cancels']==1 and d['aborts']==0 and d['power_restored']and not d['transport_ok']
 elif scenario==103:assert d['cancels']==d['aborts']==1 and d['power_restored']
 elif scenario==104:assert d['cancels']==d['aborts']==1 and not d['power_restored']and not d['safe_release']and d['enabled']==1
 elif scenario==105:assert not d['power_restored']and not d['safe_release']and d['enabled']==1
 elif scenario==106:assert d['commands']==0 and d['power_restored']and d['touch_code']==10
 elif scenario==107:assert d['IRQ_ack']==1 and d['power_restored']and d['header_length_valid']
 elif scenario in[108,110]:assert d['header_length_valid']and d['power_restored']and not d['cancels']
 elif scenario==109:assert d['cancels']==1 and not d['power_restored']and not d['safe_release']and d['enabled']==1
 elif scenario in[113,114]:assert d['header_length_valid']and d['power_restored']
 elif scenario==200:assert d['report_transport']and not d['report_header']and not d['report_body']and d['power_restored']
 elif scenario==201:assert not d['report_transport']and d['cancels']==1 and d['power_restored']
 elif scenario in[202,203]:assert d['report_transport']and not d['report_body']and d['power_restored']
 elif scenario in[204,205]:assert d['report_transport']and not d['report_body_complete']and d['power_restored']
 elif scenario in[206,207,208]:assert d['commands']==1 and d['full_checksum_valid']and not d['report_contract']and d['power_restored']
 elif scenario==209:assert not d['report_transport']and d['cancels']==1 and d['power_restored']
 elif scenario==210:assert not d['report_transport']and d['cancels']==d['aborts']==1 and not d['safe_release']and not d['power_restored']
 elif scenario in[301,302]:assert d['commands']==3 and not d['ack_transport']and not d['post_transport']and d['cancels']==1 and d['power_restored']
 elif scenario==303:assert d['commands']==3 and not d['ack_transport']and d['cancels']==d['aborts']==1 and not d['safe_release']and not d['power_restored']
 elif scenario in[305,306]:assert d['commands']==2 and not d['event_writes']and d['power_restored']
 elif scenario in[401,402]:assert d['commands']==4 and d['ack_transport']and not d['post_transport']and d['event_writes']==1 and d['cancels']==1 and d['power_restored']
 elif scenario==403:assert d['commands']==4 and d['ack_transport']and not d['post_transport']and d['cancels']==d['aborts']==1 and not d['safe_release']and not d['power_restored']
 elif scenario==404:assert d['commands']==12 and d['event_writes']==1 and d['post_header_present']==d['post_header_checksum']==1 and d['IRQ_after']==0 and d['power_restored']
 elif scenario==405:assert d['commands']==12 and d['event_writes']==1 and d['post_header_present']and not d['post_header_checksum']and d['power_restored']
 elif scenario==406:assert d['commands']==12 and d['event_writes']==1 and not d['post_header_present']and d['settle_count']==6 and d['settle_inputs']==[0]*6 and d['IRQ_after']==1 and d['power_restored']
 elif scenario in[111,112]:assert d['power_code']==3 and d['power_restored']and d['enables']==d['releases']==d['commands']==0
profiles={}
for label,scenario in [('mixed',500),('max',501),('release',509)]:
 q=run(label,scenario=scenario,fixture=a.output/('ABI-'+label+'.bin'));profiles[label]=q
 assert q['power_code']==q['touch_code']==q['poll_code']==0 and q['power_restored']and q['poll_cycles']==8
 if label=='mixed':assert q['commands']==19 and q['event_writes']==7 and q['poll_reads']==9 and q['poll_tails']==1 and q['poll_clears']==6 and q['poll_contacts']==5 and q['poll_requests']==1 and q['poll_idle']==2
 elif label=='release':assert q['commands']==13 and q['event_writes']==2 and q['poll_reads']==8 and q['poll_tails']==0 and q['poll_clears']==1 and q['poll_contacts']==1 and q['poll_idle']==7
 else:assert q['commands']==28 and q['event_writes']==9 and q['poll_reads']==16 and q['poll_tails']==q['poll_clears']==q['poll_contacts']==8
 for i in range(1,q['reads']+1):
  d=run(label+'_read_%d'%i,read=i,scenario=scenario);assert d['power_code']or d['power_restore_error']or not d['power_restored']
 for i in range(1,q['writes']+1):
  for sign in[-1,1]:
   d=run(label+'_write_%d_%d'%(sign,i),write=sign*i,scenario=scenario);assert d['power_code']or d['power_restore_error']or not d['power_restored']
 for i in range(1,q['barriers']+1):
  d=run(label+'_barrier_%d'%i,barrier=i,scenario=scenario);assert d['power_code']or d['power_restore_error']or not d['power_restored']
for scenario in range(502,509):
 d=run('invalid_poll_%d'%scenario,scenario=scenario);assert d['poll_code']==4 and d['poll_clears']==0 and d['event_writes']==1 and d['power_restored']
for scenario in [601,602,603,604,605,606]:
 d=run('poll_transport_%d'%scenario,scenario=scenario);assert d['poll_code']and d['cancels']==1
 if scenario in[603,606]:assert d['aborts']==1 and not d['power_restored']and not d['safe_release']
 else:assert d['power_restored']and d['safe_release']
for label,scenario in [('idle100',0),('mixed100',500),('max100',501),('release100',509)]:
 q=run(label,scenario=scenario,limit=100,fixture=a.output/('ABI-'+label+'.bin'));profiles[label]=q
 assert q['power_code']==q['touch_code']==q['poll_code']==q['input_error']==0 and q['power_restored'] and q['poll_cycles']==100
 if label=='max100':assert q['commands']==304 and q['event_writes']==101 and q['sink_calls']==101 and q['input_generation']==101
 if label=='release100':assert q['commands']==105 and q['event_writes']==2 and q['sink_calls']==0 and q['input_generation']==0
 # The exhaustive eight-cycle suite covers each hardware read/write/barrier;
 # late hundred-cycle boundaries additionally test the enlarged budgets.
 for key,kw in [('reads','read'),('writes','write'),('barriers','barrier')]:
  for index in sorted(set([1,q[key]//2,q[key]-1,q[key]])):
   for sign in ([-1,1] if kw=='write' else [1]):
    d=run(label+'_'+kw+str(sign*index),scenario=scenario,limit=100,**{kw:sign*index});assert d['power_code']or d['power_restore_error']or not d['power_restored']
child.stdin.close();assert child.wait(timeout=10)==0;errors=child.stderr.read();assert not errors,errors
assert all(hashlib.sha256((W/n).read_bytes()).hexdigest()==d for n,d in initial_sha.items()),'Source changed during model execution'
report={'passed':True,'cases':count,'ASan_UBSan':True,'fresh_model_state_per_case_single_sanitizer_process':True,'actual_all11_portable_C_cores_executed':True,'normal_model_reads':n['reads'],'normal_model_writes':n['writes'],'normal_SPI_barriers':n['barriers'],'all_nominal_read_failures_and_before_after_all_writes':True,'all_nominal_SPI_barrier_failures':True,'four_initial_and_max300_poll_CMDs_no_clear_replay_and_global_one_cancel_abort':True,'runtime_limits_8_and_100_same_production_source':True,'real_live_input_sink_used_in_full_hardware_model':True,'exhaustive_faults_limit8_composed_with_100cycle_boundary_checks':True,'power_reset_cleanup_requires_SPI_quiescence':True,'unknown_bus_or_pin_owner_keeps_power_clocks':True,'invalid_complete_block_checksum_refused':True,'complete242_byte_block_checksum_and_no_new_identity_claim':True,'powered_PMIC_rechecked_before_CMD':True,'IRQ25_latched_status_ack0_modeled':True,'source_sha256':{name:hashlib.sha256((W/name).read_bytes()).hexdigest()for name in names+['g56_touch.h','g56_contract.h','g56_trial.h']},'native_G37_baseline_input_sha256':hashlib.sha256(native.read_bytes()).hexdigest(),'result_code_histogram':codes,'tested_profile_statistics':{k:{n:v for n,v in row.items()if n!='wire_TX'}for k,row in profiles.items()},'limits':['All MMIO/clock/pin/FIFO/peer responses are explicit models; physical controller identity requires separate native evidence.','Saved IC-info and request bytes are fixtures; modeled ACK/post-header effects are not native evidence.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in['passed','cases','normal_model_reads','normal_model_writes']}))
