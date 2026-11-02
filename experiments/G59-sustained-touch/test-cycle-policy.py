"""Execute actual cycle policy and native adapter functions on recorded/model wire data."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g59_hardware.c').read_text()
def function(n):
 m=re.search(r'^static (?:PULONG|ULONG|int) '+n+r'\(',s,re.M);assert m,n;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{PVOID Maps\[16\];.*?\} G59_PWR_CONTEXT;',s).group();ranges=re.search(r'static const G59_RANGE G59PowerRanges\[16\]=.*?;',s).group()
prefix=r'''#include "driver-model-prefix.h"
typedef uint32_t*PULONG;typedef int BOOLEAN;
static unsigned Writes,Reads,Present=1;static uint32_t Memory[16][4096];
static int DevicePresent(void*x){return*(unsigned*)x!=0;}
static const G59_STREAM_IO Stream={&Present,0,0,0,DevicePresent};
static uint32_t ReadReg(PULONG p){Reads++;return*p;}
static void WriteReg(PULONG p,uint32_t value){Writes++;*p=value;}
#define READ_REGISTER_ULONG(p) ReadReg(p)
#define WRITE_REGISTER_ULONG(p,v) WriteReg(p,v)
'''
native_names=['G59Available','G59PowerAddress','G59PowerRead','G59NativePlan','G59NativeWord','G59PowerWrite','G59Advance'];f=a.output/'model.c';f.write_text(prefix+context+ranges+'\n'.join(function(n)for n in native_names)+(W/'cycle-policy-model.c').read_text());exe=a.output/'test';cores=['g59_plan.c','g59_report.c','g59_contract.c','g59_engine.c','g59_rsc.c','geni_fifo.c'];names=cores+['g59_hardware.c','g59_poll.h','g59_touch.h','g59_hwapi.h','cycle-policy-model.c','driver-model-prefix.h'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();before={n:sha(W/n)for n in names}
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-fsanitize=address,undefined','-I',str(W),'-I',str(W/'private/inputs'if(W/'private/inputs').is_dir()else W/'inputs'),str(f),*[str(W/n)for n in cores],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
files=[a.native]+[a.fixtures/name for name in ['ABI-good.bin','ABI-mixed.bin','ABI-max.bin','ABI-release.bin','ABI-retry.bin','ABI-retrymax.bin','ABI-idle100.bin','ABI-mixed100.bin','ABI-max100.bin','ABI-release100.bin','ABI-retry100.bin','ABI-retrymax100.bin']]
q=subprocess.run([str(exe.resolve()),*map(lambda p:str(p.resolve()),files)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);assert all(sha(W/n)==h for n,h in before.items());v.update(ASan_UBSan=True,source_sha256=before,native_capture_sha256=sha(a.native),fixture_count=len(files)-1,native_operations=0,limits=['Native G57 raw history and model fixtures are test inputs; the repeated3000-cycle run is modeled.','MMIO macros and mapped pages are explicit CPU-memory models; native G59 operation is not qualified.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
