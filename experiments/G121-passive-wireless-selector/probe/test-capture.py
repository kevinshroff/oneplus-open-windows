"""Execute exact production capture functions with explicit OS/MMIO models."""
from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output;o.mkdir(parents=True,exist_ok=False);w=Path(__file__).resolve().parent;s=(w/'g121_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:int|ULONG|void) '+name+r'\(',s,re.M);assert m,name
 i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG;typedef void*PVOID;typedef void*WDFREQUEST;
typedef struct{int64_t QuadPart;}LARGE_INTEGER,PHYSICAL_ADDRESS;
typedef struct{PHYSICAL_ADDRESS BaseAddress;LARGE_INTEGER NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define MAXULONGLONG UINT64_MAX
#define PAGE_READONLY 2u
#define PAGE_NOCACHE 512u
#define PASSIVE_LEVEL 0u
#define KernelMode 0
#define FALSE 0
#include "g121_protocol.h"
#include "g121_plan.h"
static ULONG Page[1024],Original[1024];static PHYSICAL_MEMORY_RANGE Ranges[512];
static volatile LONG G121Maps,G121Fault,G121Ready;
static unsigned MapCalls,Unmaps,FailMap,CancelAt,CancelChecks,Mutation,NoRanges,Frees,FullOS,FirmwareMatch,Processors,Build,Irql,Cases;
static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return ++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(void*p,ULONG f){assert(!p&&!f);return NoRanges?NULL:Ranges;}
static void ExFreePool(PVOID p){assert(p==Ranges);Frees++;}
static void KeMemoryBarrier(void){__sync_synchronize();}
static ULONGLONG KeQueryInterruptTime(void){return ++Time;}
static int WdfRequestIsCanceled(WDFREQUEST p){assert(p==(void*)1);return ++CancelChecks==CancelAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,size_t n,ULONG flags){assert(a.QuadPart==G121_PAGE&&n==4096&&flags==(PAGE_READONLY|PAGE_NOCACHE));MapCalls++;return FailMap?NULL:Page;}
static void MmUnmapIoSpace(PVOID p,size_t n){assert(p==Page&&n==4096);Unmaps++;}
static int FullWindows(void){return FullOS;}
static void Status(G121_STATUS*p){memset(p,0,sizeof(*p));p->Size=80;p->Version=1;p->Magic=G121_MAGIC;p->KernelBuild=Build;p->Processors=Processors;p->Irql=Irql;p->FirmwareBytes=576;p->FirmwareMatch=FirmwareMatch;p->MapCalls=G121Maps;p->Attempts=1;p->Ready=G121Ready;p->Fault=G121Fault;}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-500000);Time+=500000;if(Mutation==1)Page[0]^=1;if(Mutation==2)Page[1]^=1;if(Mutation==3)Page[0]|=1u<<9;}
'''
main=r'''
static G121_CAPTURE Out;
static void Reset(void){memset(&Out,0,sizeof(Out));memset(Page,0,sizeof(Page));memset(Ranges,0,sizeof(Ranges));MapCalls=Unmaps=FailMap=CancelAt=CancelChecks=Mutation=NoRanges=Frees=0;G121Maps=G121Fault=G121Ready=0;FullOS=FirmwareMatch=1;Processors=8;Build=26300;Irql=0;Time=0;}
static void Run(void){memcpy(Original,Page,sizeof(Page));Capture(&Out,(void*)1,123);assert(Unmaps==MapCalls-(FailMap&&MapCalls?1:0)&&G121Ready&&G121Fault==!!Out.Code&&Out.Status.Ready&&Out.Status.Fault==!!Out.Code);if(!Mutation)assert(!memcmp(Original,Page,sizeof(Page)));Cases++;}
int main(int argc,char**argv){assert(sizeof(Out)==136&&G121_PAGE==0xf153000&&G121_CONTROL_OFFSET==0&&G121_INOUT_OFFSET==4);
 for(unsigned level=0;level<2;level++){Reset();Page[0]=0x840;Page[1]=level;Run();assert(!Out.Code&&Out.CompleteMask==3&&Out.ReadBytes==16&&MapCalls==1&&Unmaps==1&&Frees==1&&Out.Nonce==123);}
 for(unsigned bit=0;bit<32;bit++){Reset();Page[0]=1u<<bit;Run();assert(Out.Code==((1u<<bit)&G121_UNSUITABLE_CONTROL?2001u:0u));}
 for(unsigned i=0;i<5;i++){Reset();if(i==0)FullOS=0;if(i==1)FirmwareMatch=0;if(i==2)Processors=1;if(i==3)Build=1;if(i==4)Irql=1;Run();assert(Out.Code==1001&&!MapCalls&&!Frees&&!Out.ReadBytes);}
 Reset();NoRanges=1;Run();assert(Out.Code==1002&&!MapCalls&&!Frees);
 for(unsigned i=0;i<4;i++){Reset();Ranges[0].BaseAddress.QuadPart=G121_PAGE+(i==0?-1:i==1?0:i==2?4095:4096);Ranges[0].NumberOfBytes.QuadPart=4096;Run();assert(Out.Code==(i<3?1002u:0u)&&Frees==1);}
 Reset();Ranges[0].BaseAddress.QuadPart=-2;Ranges[0].NumberOfBytes.QuadPart=4;Run();assert(Out.Code==1002&&!MapCalls&&Frees==1);
 Reset();for(unsigned i=0;i<512;i++){Ranges[i].BaseAddress.QuadPart=0x10000000;Ranges[i].NumberOfBytes.QuadPart=4096;}Run();assert(Out.Code==1002&&!MapCalls&&Frees==1);
 Reset();FailMap=1;Run();assert(Out.Code==1005&&MapCalls==1&&!Unmaps&&!Out.ReadBytes);
 for(unsigned i=1;i<=5;i++){Reset();CancelAt=i;Run();assert(Out.Code==1004&&Out.ReadBytes==(i<=2?0u:4u*(i-2))&&Out.CompleteMask==(i>=4?1u:0u));}
 for(unsigned i=1;i<=3;i++){Reset();Mutation=i;Run();assert(Out.Code==(i<3?2002u:2001u)&&Out.CompleteMask==3&&Out.ReadBytes==16);}
 if(argc==2){Reset();Page[0]=0x840;Page[1]=0;Run();FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&Out,1,sizeof(Out),f)==sizeof(Out));fclose(f);}
 printf("{\"passed\":true,\"cases\":%u,\"production_capture_functions\":true,\"OS_MMIO_time_modeled\":true,\"fixed_readonly_mapping_verified\":true,\"no_hardware_operations\":true}\n",Cases);
}
'''
f=o/'model.c';f.write_text(pre+'\n'.join(fn(n)for n in ['NoManagedRam','Word','Capture'])+main)
r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(f),'-o',str(o/'test')],capture_output=True,text=True);assert not r.returncode,r.stderr
r=subprocess.run([str((o/'test').resolve()),str((o/'fixture.bin').resolve())],capture_output=True,text=True);assert not r.returncode and not r.stderr,(r.stdout,r.stderr)
v=json.loads(r.stdout);v['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g121_driver.c','g121_plan.h','g121_protocol.h']};(o/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
