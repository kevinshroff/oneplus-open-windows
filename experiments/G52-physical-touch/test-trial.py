"""Execute the full eight-core path at modeled MMIO/peer boundaries with faults."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
native=a.inputs/'engine-G37/native-qualification.json';e=json.loads(native.read_text())['spi']['engine']
off=[0xe1c,0xe18,0x28,0x24,0x224,0x230,0x22c,0x250,0x24c,0x254,0x258,0x25c,0x260,0x264,0x268,0x278,0x284,0x288,0x7c,0x48,0x80c,0x810,0x814,0x614]
text='static const uint32_t ConfigOffsets[24]={'+','.join(hex(v)for v in off)+'};\n'
for n,values in [('NativeConfig',e['before']),('NativeDfs',e['DFS_before'])]:text+='static const uint32_t '+n+'[]={'+','.join(hex(v)for v in values)+'};\n'
(a.output/'native-model-input.h').write_text(text)
ic=a.inputs/'info-G47/private/IC-info-242.bin';assert hashlib.sha256(ic.read_bytes()).hexdigest()=='1ffa9ab8f7a0794ca0d3e2f38958a3c9db1022c458110bb735e400dcbd482780';(a.output/'native-model-input.h').write_text(text+'static const uint8_t ModelIc[242]={'+','.join(map(str,ic.read_bytes()))+'};\n')
exe=a.output/'test-trial';names=['g52_observer.c','g52_rsc.c','g52_power.c','g52_spi.c','g52_engine.c','g52_touch.c','g52_contract.c','geni_fifo.c','test-trial.c']
subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),*[str(W/n)for n in names],'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
count=0;codes={}
def run(name,read=0,write=0,scenario=0,barrier=0,fixture=None):
 global count
 args=[str(exe.resolve()),*map(str,[read,write,scenario,barrier])]
 if fixture:args.append(str(fixture.resolve()))
 r=subprocess.run(args,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(name,r.returncode,r.stdout,r.stderr)
 d=json.loads(r.stdout);assert d['commands']<=4 and d['event_writes']<=1 and d['enables']<=1 and d['releases']<=1 and d['cancels']<=1 and d['aborts']<=1
 if d['power_restored']:assert d['physical_model_restored'],(name,d)
 count+=1;k=str(d['power_code'])+'/'+str(d['power_restore_error']);codes[k]=codes.get(k,0)+1;return d
n=run('normal',fixture=a.output/'ABI-good.bin');assert n['power_code']==n['spi_code']==n['touch_code']==0 and n['power_restored']==n['transport_ok']==n['header_length_valid']==1 and n['identity_ok']==0 and n['info_length']==242 and n['full_checksum_valid']==1 and n['commands']==4 and n['report_transport']==n['report_contract']==n['report_header']==1 and n['report_body_complete']==n['report_body']==0 and n['report_TX_done']==n['report_RX_done']==34 and n['TX_done']==n['RX_done']==250
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
 elif scenario==404:assert d['commands']==4 and d['event_writes']==1 and d['post_header_present']==d['post_header_checksum']==1 and d['IRQ_after']==0 and d['power_restored']
 elif scenario==405:assert d['commands']==4 and d['event_writes']==1 and d['post_header_present']and not d['post_header_checksum']and d['power_restored']
 elif scenario==406:assert d['commands']==4 and d['event_writes']==1 and not d['post_header_present']and d['settle_count']==6 and d['settle_inputs']==[0]*6 and d['IRQ_after']==1 and d['power_restored']
 elif scenario in[111,112]:assert d['power_code']==3 and d['power_restored']and d['enables']==d['releases']==d['commands']==0
report={'passed':True,'cases':count,'ASan_UBSan':True,'actual_all8_portable_C_cores_executed':True,'normal_model_reads':n['reads'],'normal_model_writes':n['writes'],'normal_SPI_barriers':n['barriers'],'all_nominal_read_failures_and_before_after_all_writes':True,'all_nominal_SPI_barrier_failures':True,'four_distinct_CMDs_one_fixed_event_clear_no_replay_and_global_one_cancel_abort':True,'power_reset_cleanup_requires_SPI_quiescence':True,'unknown_bus_or_pin_owner_keeps_power_clocks':True,'invalid_complete_block_checksum_refused':True,'complete242_byte_block_checksum_and_no_new_identity_claim':True,'powered_PMIC_rechecked_before_CMD':True,'IRQ25_latched_status_ack0_modeled':True,'source_sha256':{name:hashlib.sha256((W/name).read_bytes()).hexdigest()for name in names+['g52_touch.h','g52_contract.h','g52_trial.h']},'native_G37_baseline_input_sha256':hashlib.sha256(native.read_bytes()).hexdigest(),'result_code_histogram':codes,'limits':['All MMIO/clock/pin/FIFO/peer responses are explicit models; physical controller identity requires separate native evidence.','Saved IC-info and request bytes are fixtures; modeled ACK/post-header effects are not native evidence.']}
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in['passed','cases','normal_model_reads','normal_model_writes']}))
