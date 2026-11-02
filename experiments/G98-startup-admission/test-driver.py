"""Execute actual G98 owner callbacks/input with real pthread scheduling."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--thread-sanitizer',action='store_true');a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g98_driver.c').read_text()
def function(name):
 m=re.search(r'^(?:static )?(?:ULONG|ULONGLONG|VOID|void|NTSTATUS|int) '+name+r'\(',s,re.M);assert m,name;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{.*?\}G98HID_CONTEXT;',s,re.S).group()
names=['Counter','TimeValue','Admission','WaitAdmission','CycleComplete','EpochComplete','Restored','SaveFirstFault','Retryable','RecoveryWait','OwnerLock','OwnerUnlock','Available','StopRequested','SessionStatus','RuntimeStatus','Status','G98HIDFeature','G98HIDSubmit','G98HIDStage','G98HIDPublish','RequestStop','Join','Worker','Start','G98HIDControl','G98HIDD0Entry','G98HIDD0Exit','G98HIDIoInit','G98HIDSuspend','G98HIDRestart','G98HIDSurprise','G98HIDCleanup','G98HIDFileCleanup']
names.sort(key=lambda n:s.index(function(n)))
f=a.output/'model.c';f.write_text((W/'driver-model-prefix.h').read_text()+context+(W/'driver-model-services.h').read_text()+'\n'.join(function(n)for n in names)+(W/'driver-model-main.c').read_text());exe=a.output/'model';cores=['g98hid_report.c','g98_report.c','g98hid_lifecycle.c','g98_input.c'];sources=cores+['g98_driver.c','g98hid_protocol.h','g98_protocol.h','g98_hwapi.h','driver-model-prefix.h','driver-model-services.h','driver-model-main.c'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();before={n:sha(W/n)for n in sources}
sanitizer='thread'if a.thread_sanitizer else'address,undefined'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-fsanitize='+sanitizer,'-pthread','-I',str(W),'-I',str(W/'private/inputs'if(W/'private/inputs').is_dir()else W/'inputs'),str(f),*[str(W/n)for n in cores],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);report=json.loads(q.stdout);assert all(sha(W/n)==v for n,v in before.items());report.update(sanitizer=sanitizer,source_sha256=before,native_operations=0,limits=['Kernel/WDF/VHF/firmware and hardware entry are models.','Actual callbacks use real pthread scheduling and mutex/atomic operations; native Windows lifecycle still requires separate qualification.']);(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
