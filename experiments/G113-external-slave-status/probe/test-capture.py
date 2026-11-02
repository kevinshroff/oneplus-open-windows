"""Actual full native capture/adapter/core with explicit kernel and bus models."""
from pathlib import Path
import argparse,ast,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False);w=Path(__file__).resolve().parent;s=(w/'g113_driver.c').read_text();tree=ast.parse((w/'test-native.py').read_text());pre=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='pre'for t in n.targets))
def fn(name):
 m=re.search(r'^static (?:PULONG|int|void|uint64_t) '+name+r'\(',s,re.M);assert m,name;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
ctx=re.search(r'typedef struct \{PVOID Maps\[12\].*?\}G113_CONTEXT;',s).group()
pre='#include "g113_policy.h"\n'+pre
pre=pre.replace('#define main original_core_model_main','#define main original_core_model_main\n#define Available ModelAvailable').replace('#undef main','#undef main\n#undef Available')
pre=pre.replace('MapCalls,MapFailure,RegReads,RegWrites;', 'MapCalls,MapFailure,RegReads,RegWrites,FailedMaps;').replace('return MapFailure==i+1?NULL:M.Memory[i];','if(MapFailure==i+1){FailedMaps++;return NULL;}return M.Memory[i];')
extra=r'''
#include <stddef.h>
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define PASSIVE_LEVEL 0
#define MAXULONGLONG UINT64_MAX
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g113_protocol.h"
typedef struct{int64_t QuadPart;}LARGE_INTEGER;
typedef struct{PHYSICAL_ADDRESS BaseAddress,NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
static LONG G113Ready,G113Fault;static unsigned Unmaps,FullOS,Firmware,Build,Processors,NoRanges,Freed;static PHYSICAL_MEMORY_RANGE Ranges[512];
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static int FullWindows(void){return FullOS;}
static void Status(G113_STATUS*p){memset(p,0,sizeof(*p));p->Size=80;p->Version=1;p->Magic=G113_MAGIC;p->KernelBuild=Build;p->Processors=Processors;p->FirmwareBytes=576;p->FirmwareMatch=Firmware;p->Frequency=1000000;p->MapCalls=G113Maps;p->Ready=G113Ready;p->Fault=G113Fault;}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return M.CancelAt&&M.Reads>=M.CancelAt;}
static LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*f){if(f)f->QuadPart=1000000;LARGE_INTEGER q={(int64_t)++M.Now};return q;}
static void KeStallExecutionProcessor(ULONG n){assert(n==20);M.Now+=n;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG f){assert(!p&&!f);if(NoRanges)return NULL;void*x=malloc(sizeof(Ranges));assert(x);memcpy(x,Ranges,sizeof(Ranges));return x;}
static void ExFreePool(PVOID p){Freed++;free(p);}
static void MmUnmapIoSpace(PVOID p,unsigned n){assert(p&&n==4096);Unmaps++;}
'''
main=r'''
static G113_CAPTURE Out;
static void ResetCapture(void){Reset(&M);memset(&Out,0,sizeof(Out));memset(Ranges,0,sizeof(Ranges));FailedMaps=MapCalls=MapFailure=RegReads=RegWrites=Unmaps=NoRanges=Freed=0;FullOS=Firmware=1;Build=26300;Processors=8;G113Maps=G113Ready=G113Fault=0;}
static void RunCapture(void){Capture(&Out,(void*)1,123);assert(G113Ready&&Out.Nonce==123);assert(Unmaps==MapCalls-FailedMaps);assert(Out.NativeReads==RegReads&&Out.NativeWrites==RegWrites);Cases++;}
int main(void){ResetCapture();RunCapture();assert(!Out.Result.Code&&!Out.Result.Uncertain&&Out.PolicyCommands==6&&Out.PolicyCompleted==6&&!Out.PolicyFault&&Out.NativeReads==4512&&Out.NativeWrites==33&&Out.MapCalls==7);unsigned reads=M.Reads;
 for(unsigned j=0;j<7;j++){const unsigned ids[]={1,2,4,5,6,9,10};ResetCapture();MapFailure=ids[j];RunCapture();assert(Out.Result.Code);}
 for(unsigned n=1;n<=reads;n+=3){ResetCapture();M.CancelAt=n;RunCapture();assert(!Out.Result.Uncertain);}
 for(unsigned n=1;n<=6;n++){
  ResetCapture();M.ErrorCmd=n;RunCapture();assert(Out.Result.Code==G113_BUS_ERROR&&!Out.Result.Uncertain);
  ResetCapture();M.TimeoutCmd=n;RunCapture();assert(Out.Result.Code==G113_TIMEOUT&&!Out.Result.Uncertain);
  ResetCapture();M.TimeoutCmd=n;M.NoCancel=M.NoAbort=1;RunCapture();assert(Out.Result.Code==G113_TIMEOUT&&Out.Result.Uncertain);
 }
 for(unsigned i=0;i<12;i++){ResetCapture();Ranges[0].BaseAddress.QuadPart=Pages[i];Ranges[0].NumberOfBytes.QuadPart=4096;RunCapture();assert(Out.Result.Code==1005&&!MapCalls&&!RegReads&&!RegWrites&&Freed==1);}
 ResetCapture();NoRanges=1;RunCapture();assert(Out.Result.Code==1005&&!MapCalls&&!Freed);
 ResetCapture();Ranges[0].BaseAddress.QuadPart=-4096;Ranges[0].NumberOfBytes.QuadPart=8192;RunCapture();assert(Out.Result.Code==1005&&!MapCalls&&Freed==1);
 ResetCapture();for(unsigned i=0;i<512;i++){Ranges[i].BaseAddress.QuadPart=0x100000000ULL+4096*i;Ranges[i].NumberOfBytes.QuadPart=4096;}RunCapture();assert(Out.Result.Code==1005&&!MapCalls&&Freed==1);
 for(unsigned i=0;i<4;i++){ResetCapture();if(i==0)FullOS=0;if(i==1)Firmware=0;if(i==2)Build=1;if(i==3)Processors=4;RunCapture();assert(Out.Result.Code==1004&&!MapCalls&&!Freed);}
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_native_adapter_core\":true,\"RAM_exclusion_all_unmaps_and_bus_cleanup_checked\":true,\"OS_MMIO_bus_time_explicitly_modeled\":true,\"native_operations\":0}\n",Cases);return 0;}
'''
f=o/'model.c';f.write_text(pre+ctx+extra+'\n'.join(fn(n)for n in ['NoManagedRam','WriteOffset','Address','SafeRead','NativeClocks','NativeRead','NativeWrite','DelayUs','Available','NowUs','Capture'])+main);exe=o/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),str(w/'g102_core.c'),str(w/'g113_core.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);x=json.loads(q.stdout);x['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g113_driver.c','g113_core.c','g113_core.h','g113_policy.h','g102_core.c','g102_core.h','g102_resources.h']};(o/'tests.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
