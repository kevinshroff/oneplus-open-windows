"""Match host layouts to actual ARM64 WDK-compiled ABI words."""
from pathlib import Path
import hashlib,json,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';o=p/'abi-01';o.mkdir(exist_ok=False)
fields={}
for t,names in [('OP184_STATUS_DATA','Size Version Magic Now100ns Instance D0Epoch PrepareEpoch ReleaseCalls MapCalls UnmapCalls Attempts Completed ValidCount Ticks LastSequence KernelBuild Cpus Irql FirmwareMatch Prepared D0Active MapCount Queued Busy Valid Fault Uncertain ValidationCode LastStatus ProducerQualified Reserved'),('OP184_SNAPSHOT','Status Reading Result'),('S183_RESULT','Size Version Code Uncertain Epoch Sequence Begin100ns ConfigEnd100ns GaugeEnd100ns End100ns ConfigNativeReads ConfigNativeWrites ConfigGuard GaugeNativeReads GaugeNativeWrites GaugeGuard PolicyCommands PolicyCompleted PolicyFault CancelledClean Config Gauge')]:
 fields[t]=names.split()
items=[('sizeof_'+t,'sizeof('+t+')')for t in ['OP184_STATUS_DATA','OP184_SNAPSHOT','OP184_REQUEST','S183_RESULT','S183_READING']]+[(t+'.'+n,'offsetof('+t+','+n+')')for t,names in fields.items()for n in names]
s='#include "protocol.h"\n#include <stddef.h>\nconst uint64_t Op184Abi[]={'+','.join(expr for _,expr in items)+'};\n#ifdef HOST\n#include <stdio.h>\nint main(void){for(size_t i=0;i<sizeof(Op184Abi)/8;i++)printf("%llu\\n",(unsigned long long)Op184Abi[i]);return 0;}\n#endif\n';(o/'abi.c').write_text(s)
subprocess.run(['clang','-std=c11','-DHOST','-I'+str(w/'source'),'-I'+str(w/'core'),str(o/'abi.c'),'-o',str(o/'host')],check=True);host=[int(x)for x in subprocess.check_output([str(o/'host')],text=True).split()]
prefix=json.loads((p/'compile-final/compile.json').read_text())['compile_prefix'];subprocess.run(prefix+['-c',str(o/'abi.c'),'-o',str(o/'abi.obj')],check=True);b=(o/'abi.obj').read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;sections=struct.unpack_from('<H',b,2)[0];raw=[]
for i in range(sections):
 h=b[20+40*i:60+40*i];name=h[:8].rstrip(b'\0');n,ptr=struct.unpack_from('<II',h,16)
 if name==b'.rdata'and n==len(host)*8:raw.append(b[ptr:ptr+n])
assert len(raw)==1;native=list(struct.unpack('<'+'Q'*len(host),raw[0]));assert native==host
r={'passed':True,'ARM64_layout_words':len(items),'values':dict((name,n)for(name,_),n in zip(items,host)),'protocol_sha256':hashlib.sha256((w/'source/protocol.h').read_bytes()).hexdigest(),'native_operations':0};(p/'abi.json').write_text(json.dumps(r,indent=2)+'\n');print({'ARM64_layout_words':len(items),'host_matches_WDK':True})
