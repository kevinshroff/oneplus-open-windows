"""Run the actual portable C core against each recorded native MMIO trace."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
s=json.loads(a.native.read_text());assert s['phase']=='unloaded_service_and_endpoint_absent_control8CPUs';rows=[]
for index in [1,2]:
 q=json.loads(s['jobs']['pmic-'+str(index)]['receipt']['output']);assert q['ok'];r=q['result'];assert r['operation_code']==r['stage']==0
 folder=a.output/str(index);folder.mkdir();counters=[r[k]for k in ['operation_code','stage','register_reads','observer_write_attempts','polls','observer_READ_commands']]
 data=r['revision']+r['anchor']+r['identity']+[r['pmic_status_raw']]+r['configuration'];assert len(data)==33
 text='static const G35_OBS_EVENT Tape[]={'+','.join('{%d,0x%x,0x%x}'%(x['kind'],int(x['address'],16),x['value'])for x in r['trace'])+'};\n'
 for name,values,typ in [('Counters',counters,'uint32_t'),('Completion',r['completion'],'uint32_t'),('Data',data,'uint8_t')]:text+='static const '+typ+' '+name+'[]={'+','.join(map(str,values))+'};\n'
 (folder/'native-fixture.h').write_text(text);exe=folder/'replay'
 subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(folder.resolve()),str(W/'g35_observer.c'),str(W/'replay-native.c'),'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
 run=subprocess.run([str(exe.resolve())],check=True,capture_output=True,text=True);assert not run.stderr
 result=json.loads(run.stdout);assert result['passed'];rows.append({'capture':index,'job':s['jobs']['pmic-'+str(index)]['id'],**result})
report={'passed':True,'ASan_UBSan':True,'exact_original_C_core_replays_all_native_reads_writes':True,'core_sha256':hashlib.sha256((W/'g35_observer.c').read_bytes()).hexdigest(),'source_native_state_sha256':hashlib.sha256(a.native.read_bytes()).hexdigest(),'captures':rows,'native_commands_submitted':0,'limits':['The saved native trace is the modeled bus boundary; this replay does not access the phone.','Hardware permission/timing comes from the separate native receipts.']}
(a.output/'replay.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'captures':len(rows),'native_trace_events':sum(x['events']for x in rows)}))
