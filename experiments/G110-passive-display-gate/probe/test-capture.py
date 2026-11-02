"""Execute actual fixed capture/gating code with explicit OS/MMIO/time models."""
from pathlib import Path
import argparse, hashlib, json, re, subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--native',type=Path);a=p.parse_args()
w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
s=(w/'g110_driver.c').read_text()
def fn(name):
    m=re.search(r'^static (?:int|void|ULONG|PVOID) '+name+r'\(',s,re.M);assert m,name
    i=s.index('{',m.end())+1;depth=1
    while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
    return s[m.start():i]
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;typedef int64_t LONGLONG;
typedef size_t SIZE_T;typedef int32_t LONG;typedef void*PVOID;typedef void*WDFREQUEST;
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
#define KernelMode 0
#define FALSE 0
#include "g110_protocol.h"
#include "g110_plan.h"
static volatile LONG G110Maps,G110Fault,G110Ready;
static ULONG Pages[17][1024],MapCalls,Unmaps,FailMap,CancelAt,CancelChecks,Mutation,FullOS,FirmwareMatch,Processors,Build,NoRanges;
static PHYSICAL_MEMORY_RANGE Ranges[3];static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static ULONGLONG KeQueryInterruptTime(void){return Time+=10;}
static void Status(G110_STATUS*s){memset(s,0,sizeof(*s));s->FirmwareMatch=FirmwareMatch;s->KernelBuild=Build;s->Processors=Processors;s->MapCalls=G110Maps;}
static int FullWindows(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG flags){assert(!p&&!flags);if(NoRanges)return NULL;void*out=malloc(sizeof(Ranges));assert(out);memcpy(out,Ranges,sizeof(Ranges));return out;}
static void ExFreePool(PVOID p){free(p);}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return++CancelChecks==CancelAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T n,ULONG flags){
 MapCalls++;assert(flags==(PAGE_READONLY|PAGE_NOCACHE)&&n==4096);if(MapCalls==FailMap)return NULL;
 for(unsigned i=0;i<17;i++)if((ULONGLONG)a.QuadPart==G110Plan[i].Page)return Pages[i];
 assert(!"unexpected physical map");return NULL;
}
static void MmUnmapIoSpace(PVOID p,SIZE_T n){assert(p&&n==4096);Unmaps++;}
static void KeMemoryBarrier(void){__sync_synchronize();}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-500000);Time+=500000;if(Mutation==1)Pages[1][1]=0;if(Mutation==2)Pages[4][0]=0;if(Mutation==3)Pages[5][0]^=1;}
'''
main=r'''
static G110_CAPTURE Out;
static void Reset(void){memset(&Out,0,sizeof(Out));memset(Pages,0,sizeof(Pages));memset(Ranges,0,sizeof(Ranges));
 MapCalls=Unmaps=FailMap=CancelAt=CancelChecks=Mutation=NoRanges=0;G110Maps=G110Fault=G110Ready=0;FullOS=FirmwareMatch=1;Processors=8;Build=26300;Time=0;
 Pages[0][0x0c/4]=Pages[0][0xa4/4]=Pages[2][1]=1;Pages[1][0]=Pages[3][0]=0x80000000;Pages[1][1]=Pages[3][1]=0x10000;Pages[4][0]=0x90000000;}
int main(int argc,char**argv){unsigned cases=0;
 assert(sizeof(Out)==4864&&G110_PAGES==17);
 for(unsigned i=0;i<17;i++){assert(!(G110Plan[i].Page&4095)&&G110Plan[i].Count<=12);for(unsigned j=0;j<G110Plan[i].Count;j++)assert(G110Plan[i].Off[j]<4096&&!(G110Plan[i].Off[j]&3));}
 Reset();Capture(&Out,(void*)1,123);assert(!Out.Code&&Out.CompleteMask==0x1ffff&&Out.RegionCount==17&&MapCalls==30&&Unmaps==30&&Out.Nonce==123);cases++;
 for(unsigned i=1;i<=30;i++){Reset();FailMap=i;Capture(&Out,(void*)1,123);assert(Out.Code==1005&&MapCalls==i&&Unmaps==i-1&&G110Ready&&G110Fault);cases++;}
 for(unsigned i=1;i<=30;i++){Reset();CancelAt=i;Capture(&Out,(void*)1,123);assert(Out.Code==1004&&MapCalls==i-1&&Unmaps==MapCalls);cases++;}
 for(unsigned i=0;i<4;i++){Reset();if(i==0)FullOS=0;if(i==1)FirmwareMatch=0;if(i==2)Processors=1;if(i==3)Build=1;Capture(&Out,(void*)1,123);assert(Out.Code==1001&&!MapCalls);cases++;}
 for(unsigned i=0;i<17;i++){Reset();Ranges[0].BaseAddress.QuadPart=G110Plan[i].Page;Ranges[0].NumberOfBytes.QuadPart=4096;Capture(&Out,(void*)1,123);assert(Out.Code==1002&&!MapCalls);cases++;}
 Reset();NoRanges=1;Capture(&Out,(void*)1,123);assert(Out.Code==1002&&!MapCalls);cases++;
 const unsigned pg[]={0,0,0,0,2,2,2,1,1,1,1,3,3,3,3};
 const unsigned off[]={0,3,3,0x29,0,1,1,0,0,1,1,0,0,1,1};
 const unsigned val[]={1,0,0x80000001,0,1,0,0x80000001,0,0x80000001,0,0x18000,0,0x80000001,0,0x18000};
 for(unsigned i=0;i<15;i++){Reset();Pages[pg[i]][off[i]]=val[i];Capture(&Out,(void*)1,123);assert(Out.Code==2001&&MapCalls==4&&Unmaps==4);cases++;}
 Reset();Pages[4][0]=0x80000000;Capture(&Out,(void*)1,123);assert(Out.Code==2003&&MapCalls==5&&Unmaps==5&&Out.Regions[4].Status==1&&!Out.CompleteMask);cases++;
 for(unsigned i=1;i<=3;i++){Reset();Mutation=i;Capture(&Out,(void*)1,123);assert(Out.Code==(i==1?2001u:i==2?2003u:0u)&&Unmaps==MapCalls);if(i==3)assert(Out.Regions[5].Status==3&&Out.Payload[Out.Regions[5].Offset]!=Out.Payload[Out.Regions[5].Offset+Out.Regions[5].Bytes]);cases++;}
 if(argc==2){Reset();Capture(&Out,(void*)1,123);Out.Status.Size=80;Out.Status.Version=1;Out.Status.Magic=G110_MAGIC;FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&Out,1,sizeof(Out),f)==sizeof(Out));fclose(f);}
 if(argc==3){G110_CAPTURE native;FILE*f=fopen(argv[2],"rb");assert(f&&fread(&native,1,sizeof(native),f)==sizeof(native)&&fgetc(f)==EOF);fclose(f);assert(native.Code==2001&&native.MapCalls==4&&native.ReadBytes==72);Reset();for(unsigned i=0;i<4;i++){assert(native.Regions[i].Status==1&&native.Regions[i].Address==G110Plan[i].Page&&native.Regions[i].Bytes==4*G110Plan[i].Count);for(unsigned j=0;j<G110Plan[i].Count;j++)memcpy(Pages[i]+G110Plan[i].Off[j]/4,native.Payload+native.Regions[i].Offset+4*j,4);}Capture(&Out,(void*)1,123);assert(Out.Code==native.Code&&Out.MapCalls==native.MapCalls&&Out.ReadBytes==native.ReadBytes&&!memcmp(Out.Regions,native.Regions,sizeof(native.Regions))&&!memcmp(Out.Payload,native.Payload,sizeof(native.Payload)));cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_functions\":true,\"OS_MMIO_time_modeled\":true,\"native_operations\":0,\"all_map_and_cancellation_cleanup_pass\":true}\n",cases);return 0;}
'''
path=o/'model.c';path.write_text(pre+'\n'.join(fn(n)for n in ['NoManagedRam','Word','Store','Gates','Map','Capture'])+main)
r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(path),'-o',str(o/'test')],capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test'),str(o/'fixture.bin')]+([str(a.native.resolve())]if a.native else []),capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout);report['source_hashes']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g110_driver.c','g110_plan.h','g110_protocol.h']}
(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(r.stdout)
