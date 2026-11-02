"""Replay the actual power/RSC/observer C against saved native boundaries."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--native',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
s=json.loads(a.native.read_text());row=s['jobs']['power-trial'];r=json.loads(row['receipt']['output']);assert r['ok'];r=r['result'];assert r['operation_code']==0 and r['restored']==1
head={'Code':r['operation_code'],'RestoreError':r['restore_error'],'Restored':r['restored'],'Stage':r['stage'],'TxnCount':r['transaction_count'],'PmicCount':r['pmic_count'],'EnableAttempted':r['enable_attempted'],'ReleaseAttempted':r['release_attempted'],'PreflightVerified':r['preflight_verified'],'OnVerified':r['on_verified'],'OffVerified':r['off_verified'],'RscUncertain':r['RSC_uncertain'],'ObserverUncertain':r['observer_uncertain'],'SourceStatusBaseline':r['source_status_baseline'],'ClientBefore':r['client_before'],'ClientOn':r['client_on'],'ClientAfter':r['client_after'],'GuardBefore':r['guards_before'],'GuardAfter':r['guards_after'],'Waits1ms':r['waits_1ms'],'Waits10ms':r['waits_10ms']}
def fields(d):return ''.join('.'+k+'='+('{'+','.join(map(str,v))+'}'if isinstance(v,list)else str(v))+',\n'for k,v in d.items())
def trace(rows):return '{'+','.join('{%d,0x%x,0x%x}'%(e['kind'],int(e['address'],16),e['value'])for e in rows)+'}'
text='static const G38_POWER_RESULT Expected={'+fields(head)+'.Transactions={\n'
for t in r['transactions']:
 d={'Code':t['operation_code'],'RestoreError':t['restore_error'],'Restored':t['restored'],'Stage':t['stage'],'Reads':t['register_reads'],'Writes':t['register_write_attempts'],'TraceCount':len(t['trace']),'RequestAddress':int(t['request_address'],16),'RequestData':t['request_data'],'MsgId':t['message_id'],'Completion':t['completion'],'Response':t['response'],'Triggered':t['trigger_attempted'],'Mutated':t['mutated'],'Before':t['before'],'After':t['after']}
 text+='{'+fields(d)+'.Trace='+trace(t['trace'])+'},\n'
text+='},.Pmic={\n'
for t in r['PMIC']:
 d={'Code':t['operation_code'],'Stage':t['stage'],'Reads':t['register_reads'],'Writes':t['observer_write_attempts'],'Polls':t['polls'],'Commands':t['observer_READ_commands'],'Completion':t['completion'],'Revision':t['revision'],'Anchor':t['anchor'],'Identity':t['identity'],'Status':t['pmic_status_raw'],'Configuration':t['configuration'],'TraceCount':len(t['trace'])}
 text+='{'+fields(d)+'.Trace='+trace(t['trace'])+'},\n'
text+='}};\n';(a.output/'power-native-fixture.h').write_text(text);exe=a.output/'replay'
subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),*[str(W/x)for x in['g38_rsc.c','g38_power.c','g38_observer.c','replay-native.c']],'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.returncode,q.stdout,q.stderr);report=json.loads(q.stdout)
report.update(source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in['g38_rsc.c','g38_power.c','g38_observer.c']},native_job=row['id'],native_state_sha256=hashlib.sha256(a.native.read_bytes()).hexdigest(),ASan_UBSan=True,native_commands_submitted=0,limits=['Recorded MMIO and pin reads are the replay boundary; actual hardware behavior is established separately by native receipts.'])
(a.output/'replay.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
