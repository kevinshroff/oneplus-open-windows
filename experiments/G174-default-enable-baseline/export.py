"""Export curated fresh-baseline evidence after every native step has finished."""
from pathlib import Path
import datetime,hashlib,json,shutil
w=Path(__file__).resolve().parent;p=w/'private'
repo=Path('/path/to/user/Documents/GitHub/oneplusopen-win11')
out=repo/'evidence/G174';exp=repo/'experiments/G174-default-enable-baseline'
load=lambda n:json.loads((p/n).read_text())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
for n in ['host-stage-intent.json','old-owner-close-intent.json','native-stage-intent.json','native-load-intent.json','native-start-intent.json','native-board-fv-intent.json','before-fv-hardware-intent.json','after-fv-hardware-intent.json','intent-stage.json','intent-capture.json','intent-retire.json','native-idle-intent.json']:assert load(n)['complete'],n
boot=load('fresh-boot-intent.json');assert boot['phase']=='temporary_boot_command_accepted'
session=load('native-session.json')['session'];assert session!=boot['previous_phone_session']
before=load('before-fv-hardware-summary.json');after=load('after-fv-hardware-summary.json');read=load('decoded-native-offline.json')
native=load('owner-idle-native.json')['snapshot'];state=native['state']
assert state['Phase']==3 and state['Fault']==0 and not state['Pending']and not state['BatchActive']
assert state['PulseAttempted']==0 and not state['PulseEnableAcked']and not state['PulseDisableAcked']
assert read['operation_code']==0 and not read['uncertain_read']and read['post_routes_verified']==1 and read['commands']==11
assert read['telemetry']['charge_enable_bit']==1,'Record an unexpected gate context separately; do not call it enable1'
assert after['config']['float_voltage_mV']==4470
out.mkdir(parents=True,exist_ok=True);exp.mkdir(parents=True,exist_ok=True)
for f in w.glob('*.py'):shutil.copyfile(f,exp/f.name)
for f in w.glob('*.ps1'):shutil.copyfile(f,exp/f.name)
def emit(name,value):(out/name).write_text(json.dumps(value,indent=2)+'\n')
manifest=load('package.json')
emit('reused-tools.json',{'campaign':'G174','files':{n:{k:v for k,v in item.items()if k!='path'}for n,item in manifest['files'].items()},'compiled_sources_rechecked':True,'new_native_binaries':0,'SET24_steps':0,'orchestration_sha256':manifest['python_sha256']})
emit('native-read.json',read)
rows=[]
enable_rows={}
for phase in ['before-fv','after-fv']:
 intent=load(phase+'-hardware-intent.json');result=intent['results']['G167']['result']
 rows.append({'phase':phase,'capture_sha256':intent['results']['G167']['capture_sha256'],'traces':result['traces']})
 gate=next(t for t in result['traces']if t['address']=='SID7:0x2640')
 enable_rows[phase]=bytes.fromhex(gate['value_hex'])[6]&1
 assert enable_rows[phase]==1
emit('native-register-rows.json',rows)
def status_bytes(traces):
 first=next(t for t in traces if t['address']=='SID7:0x2606')
 tail=next(t for t in traces if t['address']=='SID7:0x260e')
 b=bytes.fromhex(first['value_hex']+tail['value_hex']);assert len(b)==10
 return b
changed={}
for x,y in zip(rows[0]['traces'],rows[1]['traces']):
 assert x['address']==y['address']
 for i,(a,b)in enumerate(zip(bytes.fromhex(x['value_hex']),bytes.fromhex(y['value_hex']))):
  if a!=b:changed[f"SID7:0x{int(x['address'].split('0x')[1],16)+i:04x}"]={'before':a,'after':b}
old=json.loads((repo/'evidence/G171/native-register-rows.json').read_text())
old_status=status_bytes(old['phases']['during-pulse']['traces']);new_status=status_bytes(rows[1]['traces'])
assert changed=={'SID7:0x260b':{'before':95,'after':87},'SID7:0x2658':{'before':95,'after':87}}
emit('status-comparison.json',{'same_boot_FV_changes':changed,'G170_during_pulse_status_hex':old_status.hex(),'G174_default_enable_after_FV_status_hex':new_status.hex(),'across_boot_changed_bytes':[{'address':f'SID7:0x{0x2606+i:04x}','G170':a,'G174':b}for i,(a,b)in enumerate(zip(old_status,new_status))if a!=b],'interpretation':'260D differs across boots (38h to18h); its meaning and cause remain unqualified. Both captures have enable1. Do not attribute it to a particular control or call it a fault. The old installed getter omits this byte.','new_native_operations':0})
emit('paired-observations.json',{'before_fixed_FV':before,'after_fixed_FV':after,'limits':['Configuration intervals use QPC; do not compare them directly with interrupt times.','Finite transport observers are not a production resource or power lease.','Configured/effective current limits are not measured current.']})
contracts={'subject_sha256':'889266377fc9ff1d5910783f56a54dd39466b291603ac38c880b1ad8c5b2ce50','observed':{'status_R2_wrapper':'600b9220 validates chip<11 and non-null output, dispatches selected6038ba2c+chip*24h pointer callback+38h, then returns callback status.','selected_static_memory':'6038ba20..6038ba6f are zero in the artifact. This does not establish runtime registration or its selected backend.','consumers':'60042a80,601ac430 and60056660 consume the first returned byte as charging state. They do not establish all status-field meanings.','old_status_name':'No direct xrefs were returned for old name6024a992; this does not prove the API absent.'},'evidence':{n:load(n)['evidence_id']for n in ['REA-statusR2.json','REA-selected-static-bytes.json','REA-statusR2-consumers.json','REA-status-consumer-log.json']},'not_qualified':['Current R2 backend/complete ABI and native cause of DISABLED','Meaning of260C/260D and remaining status bits','Interpreting old installed getter output as current R2 layout'],'new_phone_operations':0}
emit('compiled-status-contracts.json',contracts)
result={'campaign':'G174','session':session,'scope':'Fresh default-enable1 baseline, fixed4470mV FV correction only; no SET24','software_fastboot_cycle':6,'unchanged_G155_boot':5,'image_sha256':boot['image_sha256'],'old_owner_close':{k:load('old-owner-close-intent.json')['final'][k]for k in ['SafeToUnload','MapsLive','state']},'fresh_report':{k:load('fresh-DSP-report-native.json')['report'][k]for k in ['table_sha256','report_valid','stable_double_read','phase','fault','PAS_sequence_accepted','main_public_success']},'paired_observer_batches':2,'fixed_SPMI_READs':49,'gauge_queries':40,'FV_SETs':1,'charge_enable_SETs':0,'charge_disable_SETs':0,'paired_charge_enable_bits':enable_rows,'effective_input':read['telemetry'],'current_owner':{k:native[k]for k in ['Running','MapsLive','last_command_id','timer_calls','state']},'finite_observers_retired_and_separately_absent':True,'physical_charging_qualified':False,'production_power_lease_qualified':False,'all_six_goal_areas_complete':False,'limits':['A charge-enable bit1 and nonzero input-current limit do not prove physical charging.','No additional enable pulse was attempted.','Older installed status output is not a qualified decoder of the current R2 ABI.'],'next':'Resolve selected R2 backend/current status semantics and remaining charger inhibit before another policy change; retain healthy owner and autonomous recovery.'}
emit('native-analysis.json',result)
print(json.dumps({'session':session,'telemetry':read['telemetry'],'owner_last_command':native['last_command_id'],'SET24':0,'output':str(out)},indent=2))
