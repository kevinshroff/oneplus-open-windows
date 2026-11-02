"""Exercise the actual finite capture, including RAM exclusion and unmapping."""
from pathlib import Path
import re,argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=False);s=(w/'g112_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:int|PULONG|uint64_t|void) '+name+r'\(',s,re.M);assert m,name
 i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint32_t ULONG,*PULONG;typedef unsigned char UCHAR,*PUCHAR;typedef uint64_t ULONGLONG;typedef int64_t LONGLONG;typedef int32_t LONG;typedef void*PVOID;typedef size_t SIZE_T;typedef void*WDFREQUEST;
typedef struct{LONGLONG QuadPart;}PHYSICAL_ADDRESS,LARGE_INTEGER;
typedef struct{PHYSICAL_ADDRESS BaseAddress,NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define PAGE_READONLY 2
#define PAGE_NOCACHE 512
#define PASSIVE_LEVEL 0
#define MAXULONGLONG UINT64_MAX
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g112_core.c"
#include "g112_protocol.h"
static volatile LONG G112Maps,G112Ready,G112Fault;
'''
pre+=re.search(r'static const ULONG Pages\[\].*?;',s).group()+'\n'+re.search(r'typedef struct \{PVOID Maps\[12\].*?\}G112_CONTEXT;',s).group()+'\n'
pre+=r'''
static ULONG Memory[12][1024],MapCalls,Unmaps,Reads,FailMap,CancelAt,CancelChecks,NoRanges,RangesFreed,FullOS,Firmware,Build,Processors;static PHYSICAL_MEMORY_RANGE Ranges[512];static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static void Status(G112_STATUS*p){memset(p,0,sizeof(*p));p->Size=80;p->Version=1;p->Magic=G112_MAGIC;p->KernelBuild=Build;p->Processors=Processors;p->FirmwareBytes=576;p->FirmwareMatch=Firmware;p->Frequency=1000000;p->MapCalls=G112Maps;p->Ready=G112Ready;p->Fault=G112Fault;}
static int FullWindows(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG f){assert(!p&&!f);if(NoRanges)return NULL;void*x=malloc(sizeof(Ranges));assert(x);memcpy(x,Ranges,sizeof(Ranges));return x;}
static void ExFreePool(PVOID p){RangesFreed++;free(p);}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return CancelAt&&++CancelChecks>=CancelAt;}
static LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*f){if(f)f->QuadPart=1000000;LARGE_INTEGER r={(LONGLONG)++Time};return r;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T n,ULONG flags){MapCalls++;assert(n==4096&&flags==(PAGE_READONLY|PAGE_NOCACHE));if(MapCalls==FailMap)return NULL;for(unsigned i=0;i<12;i++)if(a.QuadPart==Pages[i])return Memory[i];assert(0);return NULL;}
static void MmUnmapIoSpace(PVOID p,SIZE_T n){assert(p&&n==4096);Unmaps++;}
static PULONG At(ULONG at){for(unsigned i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<4096)return Memory[i]+(at-Pages[i])/4;assert(0);return NULL;}
static ULONG ReadReg(PULONG p){Reads++;return*p;}
#define READ_REGISTER_ULONG(p) ReadReg(p)
'''
main=r'''
static G112_CAPTURE Out;static unsigned Cases;
static void Reset(void){memset(&Out,0,sizeof(Out));memset(Memory,0,sizeof(Memory));memset(Ranges,0,sizeof(Ranges));MapCalls=Unmaps=Reads=FailMap=CancelAt=CancelChecks=NoRanges=RangesFreed=0;FullOS=Firmware=1;Build=26300;Processors=8;Time=0;G112Maps=G112Ready=G112Fault=0;
 for(unsigned i=0;i<2;i++){const G112_CONTROLLER*c=G112Controllers+i;for(unsigned j=0;j<3;j++){const G112_CLOCK*k=c->Clocks+j;*At(k->Vote)|=k->Mask;*At(k->Cbcr)=k->Hwcg?0x80000002:0;}*At(c->Root)=0x80000000;*At(c->Root+4)=1;for(unsigned j=0;j<2;j++){*At(0xf100000+c->Pins[j]*4096)=(c->Mux[j]<<2)|3;*At(0xf100004+c->Pins[j]*4096)=1;}*At(c->Base+0x68)=0x303;}
 *At(0x8c0004)=0x30090000;
}
static void Run(void){Capture(&Out,(void*)1,123);assert(Unmaps==MapCalls-((FailMap&&MapCalls>=FailMap)?1:0));assert(G112Ready&&Out.NativeReads==Reads&&Out.MapCalls==MapCalls&&Out.Nonce==123);Cases++;}
int main(void){Reset();Run();assert(!Out.Result.Code&&Out.Result.ReadyMask==3&&MapCalls==11&&Reads==728&&RangesFreed==1);unsigned maps=MapCalls;
 for(unsigned i=1;i<=maps;i++){Reset();FailMap=i;Run();assert(Out.Result.Code&&Out.MapCalls==i);}
 for(unsigned i=1;i<=800;i++){Reset();CancelAt=i;Run();assert(Out.Result.Code||Out.Result.ReadyMask==3);}
 for(unsigned i=0;i<12;i++){Reset();Ranges[0].BaseAddress.QuadPart=Pages[i];Ranges[0].NumberOfBytes.QuadPart=4096;Run();assert(Out.Result.Code==1005&&!MapCalls&&!Reads&&RangesFreed==1);}
 Reset();NoRanges=1;Run();assert(Out.Result.Code==1005&&!MapCalls&&!Reads&&!RangesFreed);
 Reset();Ranges[0].BaseAddress.QuadPart=-4096;Ranges[0].NumberOfBytes.QuadPart=8192;Run();assert(Out.Result.Code==1005&&!MapCalls&&!Reads&&RangesFreed==1);
 Reset();for(unsigned i=0;i<512;i++){Ranges[i].BaseAddress.QuadPart=0x100000000ULL+4096*i;Ranges[i].NumberOfBytes.QuadPart=4096;}Run();assert(Out.Result.Code==1005&&!MapCalls&&!Reads&&RangesFreed==1);
 for(unsigned i=0;i<4;i++){Reset();if(i==0)FullOS=0;if(i==1)Firmware=0;if(i==2)Build=1;if(i==3)Processors=4;Run();assert(Out.Result.Code==1004&&!MapCalls&&!Reads&&!RangesFreed);}
 Reset();*At(G112Controllers[1].Clocks[0].Vote)&=~G112Controllers[1].Clocks[0].Mask;Run();assert(!Out.Result.Code&&Out.Result.ReadyMask==1&&MapCalls==10);
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_adapter_core_executed\":true,\"RAM_exclusion_and_all_unmaps_verified\":true,\"OS_MMIO_time_explicitly_modeled\":true,\"native_operations\":0}\n",Cases);return 0;}
'''
f=o/'model.c';f.write_text(pre+'\n'.join(fn(n)for n in ['NoManagedRam','Address','SafeRead','NativeClocks','NativeRead','Available','NowUs','Capture'])+main);exe=o/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g112_driver.c','g112_core.c','g112_core.h','g112_resources.h','g112_protocol.h']};(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
