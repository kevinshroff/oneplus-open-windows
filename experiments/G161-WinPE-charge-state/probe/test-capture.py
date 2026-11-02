"""Actual capture/adapter/core with explicit per-APID MMIO, OS and time models."""
from pathlib import Path
import argparse,re,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
s=(w/'g161_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:int|PULONG|uint64_t|void) '+name+r'\(',s,re.M);assert m,name
 i=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 512
#define PASSIVE_LEVEL 0
#define MAXULONGLONG UINT64_MAX
#define KernelMode 0
#define FALSE 0
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g161_protocol.h"
#include "g111_core.c"
static volatile LONG G161Maps,G161Ready,G161Fault;
static const ULONG Pages[5]={0xc400000,0xc402000,0xc42d000,0xc443000,0xc445000};
typedef struct{PVOID Maps[5];WDFREQUEST Request;ULONG Own,Reads,Writes,Guard;ULONGLONG Frequency;}G111_CONTEXT;
static ULONG Mem[5][1024],Cmd[5],Reg[5][256],Issued,MapCalls,Unmaps,ReadCalls,WriteCalls,CancelAt,CancelChecks,FailMap,TimeoutAt,ErrorAt,SlowPoll,Poll[5],Mutation,NoRanges,FullOS,Firmware,Build,Processors;
static PHYSICAL_MEMORY_RANGE Ranges[3];static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static ULONGLONG KeQueryInterruptTime(void){return Time*10;}
static LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*f){if(f)f->QuadPart=1000000;LARGE_INTEGER v={(LONGLONG)++Time};return v;}
static void Status(G161_STATUS*p){memset(p,0,sizeof(*p));p->Size=80;p->Version=1;p->Magic=G161_MAGIC;p->KernelBuild=Build;p->Processors=Processors;p->FirmwareBytes=576;p->FirmwareMatch=Firmware;p->Frequency=1000000;p->Attempts=1;p->MapCalls=G161Maps;p->Ready=G161Ready;p->Fault=G161Fault;}
static int WinPE(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG f){assert(!p&&!f);if(NoRanges)return NULL;void*x=malloc(sizeof(Ranges));assert(x);memcpy(x,Ranges,sizeof(Ranges));return x;}
static void ExFreePool(PVOID p){free(p);}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return ++CancelChecks==CancelAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T n,ULONG flags){MapCalls++;assert(n==4096);if(MapCalls==FailMap)return NULL;for(unsigned i=0;i<5;i++)if(a.QuadPart==Pages[i]){assert(flags==((i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE));return Mem[i];}assert(!"unknown map");return NULL;}
static void MmUnmapIoSpace(PVOID p,SIZE_T n){assert(p&&n==4096);Unmaps++;}
static void KeStallExecutionProcessor(ULONG n){assert(n==1);Time+=n;}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-200000);Time+=20000;if(Mutation==1)Mem[1][(G111Targets[2].Apid*4)/4]^=1;if(Mutation==2)Reg[2][6]^=1;}
static ULONG Phys(PULONG p){for(unsigned i=0;i<5;i++)if((uintptr_t)p>=(uintptr_t)Mem[i]&&(uintptr_t)p<(uintptr_t)(Mem[i]+1024))return Pages[i]+(ULONG)((uintptr_t)p-(uintptr_t)Mem[i]);assert(!"pointer outside maps");return 0;}
static ULONG ModelRead(PULONG p){ULONG at=Phys(p);assert(G111ReadAllowed(at));ReadCalls++;
 for(unsigned i=0;i<5;i++){ULONG base=G111Base(i);if(at==base)return Cmd[i];if(at==base+8){if(!Cmd[i])return 1;if(Issued==TimeoutAt)return 0;if(++Poll[i]<SlowPoll)return 0;return Issued==ErrorAt?3:1;}if(at==base+0x18||at==base+0x1c){ULONG n=(Cmd[i]&7)+1,off=(Cmd[i]>>4)&255,start=at==base+0x18?0:4,v=0;for(ULONG j=0;j<4&&j+start<n;j++)v|=Reg[i][off+start+j]<<(8*j);return v;}}
 return *p;
}
static void ModelWrite(PULONG p,ULONG v){ULONG at=Phys(p);assert(G111WriteAllowed(at,v));assert((v>>24)==8);WriteCalls++;for(unsigned i=0;i<5;i++)if(at==G111Base(i)){Cmd[i]=v;Poll[i]=0;Issued++;return;}assert(!"nonfixed write");}
#define READ_REGISTER_ULONG(p) ModelRead(p)
#define WRITE_REGISTER_ULONG(p,v) ModelWrite(p,v)
'''
main=r'''
static G161_CAPTURE Out;
static void Reset(void){memset(&Out,0,sizeof(Out));memset(Mem,0,sizeof(Mem));memset(Reg,0,sizeof(Reg));memset(Cmd,0,sizeof(Cmd));memset(Poll,0,sizeof(Poll));memset(Ranges,0,sizeof(Ranges));Issued=MapCalls=Unmaps=ReadCalls=WriteCalls=CancelAt=CancelChecks=FailMap=TimeoutAt=ErrorAt=Mutation=NoRanges=0;SlowPoll=2;FullOS=Firmware=1;Build=26100;Processors=8;Time=0;G161Maps=G161Ready=G161Fault=0;
 Mem[0][0]=0x70000001;Mem[0][1]=0x80040300;Mem[0][2]=0x100;
 for(unsigned i=0;i<5;i++){Mem[1][G111Targets[i].Apid]=G111Targets[i].Map;Mem[2][G111Targets[i].Apid]=G111Targets[i].Owner;}
 Reg[0][4]=0x51;Reg[0][5]=0x47;Reg[0][6]=1;
 for(unsigned i=1;i<5;i++){Reg[i][4]=2;Reg[i][5]=i==1?0xa8:0xa0+i;}
 Reg[2][6]=7;Reg[2][0x50]=4;Reg[2][0x54]=6;Reg[2][0x58]=87;Reg[4][0xa]=Reg[4][0xb]=1;
}
static void Run(void){Capture(&Out,(void*)1,123);assert(Unmaps==MapCalls-(FailMap?1:0)&&G161Ready);assert(Out.NativeWrites==WriteCalls&&Out.NativeReads==ReadCalls);}
int main(int argc,char**argv){unsigned cases=0;Reset();Run();assert(!Out.Result.Code&&Out.Result.Commands==17&&Out.Result.TraceCount==17&&Out.Result.PostRoutesVerified&&Out.NativeGuard==0&&Out.Result.EndUs-Out.Result.BeginUs>=20000);cases++;unsigned checks=CancelChecks;
 if(argc==2){FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&Out,1,sizeof(Out),f)==sizeof(Out));fclose(f);}
 for(unsigned i=1;i<=5;i++){Reset();FailMap=i;Run();assert(Out.Result.Code==1005&&!WriteCalls);cases++;}
 for(unsigned i=0;i<5;i++){Reset();Ranges[0].BaseAddress.QuadPart=Pages[i];Ranges[0].NumberOfBytes.QuadPart=4096;Run();assert(Out.Result.Code==1002&&!MapCalls);cases++;}
 Reset();NoRanges=1;Run();assert(Out.Result.Code==1002&&!MapCalls);cases++;
 for(unsigned i=0;i<4;i++){Reset();if(i==0)FullOS=0;if(i==1)Firmware=0;if(i==2)Build=1;if(i==3)Processors=1;Run();assert(Out.Result.Code==1001&&!MapCalls);cases++;}
 for(unsigned i=1;i<=checks;i++){Reset();CancelAt=i;Run();assert(Out.Result.Code&&WriteCalls<=17);cases++;}
 for(unsigned i=1;i<=17;i++){Reset();TimeoutAt=i;Run();assert(Out.Result.Code==G111_TIMEOUT&&WriteCalls==i&&Out.Result.Trace[i-1].Flags==15);cases++;Reset();ErrorAt=i;Run();assert(Out.Result.Code==G111_COMPLETION&&WriteCalls==i&&Out.Result.Trace[i-1].Flags==31);cases++;}
 for(unsigned i=0;i<3;i++){Reset();Mem[0][i]^=1;Run();assert(Out.Result.Code==G111_ARBITER&&!WriteCalls);cases++;}
 for(unsigned i=0;i<5;i++)for(unsigned j=0;j<2;j++){Reset();Mem[j+1][G111Targets[i].Apid]^=1;Run();assert(Out.Result.Code==G111_ROUTE&&WriteCalls==i);cases++;}
 for(unsigned i=0;i<5;i++){Reset();Cmd[i]=0x08000007;TimeoutAt=0;Run();assert(Out.Result.Code==G111_PENDING&&WriteCalls==i);cases++;}
 for(unsigned i=0;i<5;i++){Reset();Reg[i][4]^=1;Run();assert(Out.Result.Code==G111_IDENTITY&&WriteCalls==i+1);cases++;}
 Reset();Reg[0][5]^=1;Run();assert(Out.Result.Code==G111_IDENTITY&&WriteCalls==1);cases++;
 Reset();Reg[1][5]=0x7f;Run();assert(!Out.Result.Code);cases++;
 Reset();Reg[1][5]=0;Run();assert(Out.Result.Code==G111_IDENTITY&&WriteCalls==2);cases++;
 Reset();Mutation=1;Run();assert(Out.Result.Code==G111_ROUTE&&WriteCalls==16);cases++;
 Reset();Mutation=2;Run();assert(!Out.Result.Code&&Out.Result.Values[5][0]!=Out.Result.Values[16][0]);cases++;
 const unsigned touch[]={0,117,145,559,560,583,695};for(unsigned i=0;i<5;i++)for(unsigned j=0;j<7;j++){assert(G111Targets[i].Apid!=touch[j]);assert(!G111WriteAllowed(0xc440000+touch[j]*0x20,0x08000007));}cases++;
 G111_CONTEXT c;Reset();memset(&c,0,sizeof(c));c.Own=1;c.Request=(void*)1;for(unsigned i=0;i<5;i++)c.Maps[i]=Mem[i];
 for(unsigned i=0;i<17;i++){const G111_QUERY*q=G111Queries+i;assert(Address(&c,G111Base(q->Target),1,0x08000000|(q->Offset<<4)|(q->Bytes-1)));assert(!Address(&c,G111Base(q->Target)+0x18,1,0x08000007));assert(!Address(&c,G111Base(q->Target),1,7));cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_adapter_and_core\":true,\"OS_per_APID_MMIO_time_modeled\":true,\"all_map_cleanup_pass\":true,\"native_operations\":0}\n",cases);return 0;}
'''
code=pre+'\n'.join(fn(n)for n in ['NoManagedRam','Address','NativeRead','Available','NativeWrite','WaitUs','WaitInterval','NowUs','Capture'])+main
path=o/'model.c';path.write_text(code);cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(path),'-o',str(o/'test')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test'),str(o/'fixture.bin')],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout);report['sources']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g161_driver.c','g111_core.c','g111_core.h','g161_protocol.h']};(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(r.stdout)
