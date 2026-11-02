"""Execute the new WinPE capture wrapper with the exact qualified gauge core."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False,parents=True)
s=(w/'g160_driver.c').read_text();body=s[s.index('static int ReservedRam'):s.index('VOID G160Control')]
pre=r'''
#include "g104_policy.h"
#define main original_core_model_main
#define Available ModelAvailable
#include "test-core.c"
#undef main
#undef Available
#include <stddef.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG;typedef void*PVOID;typedef uint32_t*PULONG;typedef uint8_t*PUCHAR;typedef void*WDFREQUEST;typedef struct{int64_t QuadPart;}PHYSICAL_ADDRESS,LARGE_INTEGER;
typedef struct{PHYSICAL_ADDRESS BaseAddress,NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 512
#define MAXULONGLONG UINT64_MAX
#define RTL_NUMBER_OF(x) (sizeof(x)/sizeof((x)[0]))
#define PASSIVE_LEVEL 0
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g160_protocol.h"
static volatile LONG G160Maps,G160Ready,G160Fault;
static Model M;static unsigned MapCalls,Unmaps,MapFailure,RegReads,RegWrites,FullPE,Build,Processors,Irql,Firmware,NoRanges;
static PHYSICAL_MEMORY_RANGE Ranges[513];
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static int WinPE(void){return FullPE;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG flags){assert(!p&&!flags);if(NoRanges)return NULL;void*r=malloc(sizeof(Ranges));assert(r);memcpy(r,Ranges,sizeof(Ranges));return r;}
static void ExFreePool(PVOID p){free(p);}
static void Status(G160_STATUS*s){memset(s,0,sizeof(*s));s->Size=80;s->Version=1;s->Magic=G160_MAGIC;s->KernelBuild=Build;s->Processors=Processors;s->Irql=Irql;s->FirmwareBytes=576;s->FirmwareMatch=Firmware;s->Frequency=19200000;s->MapCalls=G160Maps;s->Attempts=1;s->Ready=G160Ready;s->Fault=G160Fault;}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,unsigned bytes,unsigned flags){assert(bytes==4096);for(unsigned i=0;i<12;i++)if(a.QuadPart==Pages[i]){assert(flags==(((i==8||i==10)?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE));MapCalls++;return MapFailure==i+1?NULL:M.Memory[i];}assert(0);return NULL;}
static void MmUnmapIoSpace(PVOID p,unsigned n){assert(p&&n==4096);Unmaps++;}
static ULONG OffsetOf(PULONG p){for(unsigned i=0;i<12;i++)if(p>=M.Memory[i]&&p<M.Memory[i]+1024)return Pages[i]+(ULONG)((p-M.Memory[i])*4);assert(0);return 0;}
static uint32_t ReadReg(PULONG p){uint32_t v;RegReads++;assert(Read(&M,OffsetOf(p),&v));return v;}
static void WriteReg(PULONG p,uint32_t v){RegWrites++;assert(Write(&M,OffsetOf(p),v));}
#define READ_REGISTER_ULONG(p) ReadReg(p)
#define WRITE_REGISTER_ULONG(p,v) WriteReg(p,v)
static int WdfRequestIsCanceled(WDFREQUEST p){assert(p==(void*)1);return !ModelAvailable(&M);}
static void KeStallExecutionProcessor(unsigned us){Delay(&M,us);}
static LARGE_INTEGER KeQueryPerformanceCounter(PVOID p){assert(!p);LARGE_INTEGER t={(int64_t)(Now(&M)*192/10)};return t;}
'''
main=r'''
static G160_CAPTURE*Out;
static void ResetCapture(void){Reset(&M);memset(Out,0,sizeof(*Out));memset(Ranges,0,sizeof(Ranges));G160Maps=G160Ready=G160Fault=0;MapCalls=Unmaps=MapFailure=RegReads=RegWrites=NoRanges=0;FullPE=Firmware=1;Processors=8;Build=26100;Irql=0;}
static void Save(const char*folder,const char*name){char path[4096];int n=snprintf(path,sizeof(path),"%s/%s.bin",folder,name);assert(n>0&&(size_t)n<sizeof(path));FILE*f=fopen(path,"wbx");assert(f&&fwrite(Out,1,sizeof(*Out),f)==sizeof(*Out));fclose(f);}
static void CaptureOnce(void){Capture(Out,(void*)1,0x1234);assert(Out->Nonce==0x1234&&G160Ready&&Out->Status.Ready&&((Out->Result.Code!=0)==(G160Fault!=0)));}
int main(int argc,char**argv){assert(argc==2);unsigned cases=0;Out=calloc(1,sizeof(*Out));assert(Out);
 ResetCapture();CaptureOnce();assert(!Out->Result.Code&&Out->Result.Commands==46&&Out->Result.Completed==46&&Out->Result.QueryMask==0xfffff&&Out->Result.CleanMask==3&&Out->Result.RestoredMask==3&&Out->PolicyCommands==46&&Out->PolicyCompleted==46&&!Out->PolicyFault&&MapCalls==11&&Unmaps==11&&RegWrites==248);Save(argv[1],"success");cases++;
 for(unsigned i=0;i<5;i++){ResetCapture();if(i==0)FullPE=0;if(i==1)Build=26300;if(i==2)Processors=1;if(i==3)Irql=1;if(i==4)Firmware=0;CaptureOnce();assert(Out->Result.Code==1004&&!RegReads&&!RegWrites&&!MapCalls);cases++;}
 for(unsigned i=0;i<12;i++)for(unsigned edge=0;edge<2;edge++){ResetCapture();Ranges[0].BaseAddress.QuadPart=(int64_t)Pages[i]+(edge?4095:-4095);Ranges[0].NumberOfBytes.QuadPart=4096;CaptureOnce();assert(Out->Result.Code==1005&&!RegReads&&!RegWrites&&!MapCalls);cases++;}
 ResetCapture();NoRanges=1;CaptureOnce();assert(Out->Result.Code==1005&&!RegReads&&!RegWrites);Save(argv[1],"refused-RAM");cases++;
 ResetCapture();Ranges[0].BaseAddress.QuadPart=-3;Ranges[0].NumberOfBytes.QuadPart=4;CaptureOnce();assert(Out->Result.Code==1005&&!RegReads&&!RegWrites);cases++;
 ResetCapture();for(unsigned i=0;i<512;i++){Ranges[i].BaseAddress.QuadPart=0x100000000LL;Ranges[i].NumberOfBytes.QuadPart=4096;}CaptureOnce();assert(Out->Result.Code==1005&&!RegReads&&!RegWrites);cases++;
 for(unsigned i=1;i<=12;i++){ResetCapture();MapFailure=i;CaptureOnce();if(i==12){assert(!Out->Result.Code);}else assert(Out->Result.Code&&!RegWrites);assert(Unmaps<=11&&Unmaps<MapCalls+(i==12));cases++;}
 ResetCapture();*At(&M,0x880068)=0;CaptureOnce();assert(Out->Result.Code&&!RegWrites&&!Out->Result.Uncertain);Save(argv[1],"refused-live-state");cases++;
 ResetCapture();M.CancelAt=100;CaptureOnce();assert(Out->Result.Code&&!Out->Result.Uncertain);cases++;
 ResetCapture();M.TimeoutCmd=1;CaptureOnce();assert(Out->Result.Code==G104_TIMEOUT&&!Out->Result.Uncertain&&Out->Result.Cancels==1);Save(argv[1],"timeout-cleaned");cases++;
 ResetCapture();M.BadID=1;CaptureOnce();assert(Out->Result.Code==G104_IDENTITY&&!Out->Result.Uncertain&&Out->Result.RestoredMask==1);Save(argv[1],"wrong-ID-cleaned");cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_WinPE_capture_and_G104_core\":true,\"physical_MMIO_OS_time_explicitly_modeled\":true,\"native_operations\":0}\n",cases);free(Out);return 0;
}
'''
(o/'model.c').write_text(pre+body+main)
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(o/'model.c'),str(w/'g102_core.c'),str(w/'g104_core.c'),'-o',str(o/'test')],capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,q.stderr
q=subprocess.run([str(o/'test'),str(o)],capture_output=True,text=True);(o/'run.txt').write_text(q.stdout+q.stderr);assert not q.returncode,q.stdout+q.stderr
r=json.loads(q.stdout);r['source_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest()for f in w.iterdir()if f.suffix in ['.c','.h','.inc']and not f.name.startswith('test-')};(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
