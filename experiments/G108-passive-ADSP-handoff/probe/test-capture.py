"""Execute actual capture functions with explicit OS/map/time/shared-RAM models."""
from pathlib import Path
import argparse, hashlib, json, re, subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=Path(__file__).resolve().parent;o=a.output.resolve();assert not o.exists();o.mkdir(parents=True)
s=(w/'g108_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:int|void) '+name+r'\(',s,re.M);assert m
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
#include "g108_protocol.h"
#include "g108_select.h"
static volatile LONG G108Maps,G108Fault,G108Ready;
static UCHAR Smem[0x200000],Xbl[0x40000],Log[0x8000],Imem[0x1000];
static PHYSICAL_MEMORY_RANGE Ranges[4];
static ULONG MapCalls,Unmaps,FailMap,CancelAt,CancelChecks,Mutation,FullOS,FirmwareMatch,Processors,Build,NoRanges;
static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static ULONGLONG KeQueryInterruptTime(void){return Time+=10;}
static void Status(G108_STATUS*s){memset(s,0,sizeof(*s));s->FirmwareMatch=FirmwareMatch;s->KernelBuild=Build;s->Processors=Processors;s->MapCalls=G108Maps;}
static int FullWindows(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG flags){assert(!p&&!flags);if(NoRanges)return NULL;void*out=malloc(sizeof(Ranges));assert(out);memcpy(out,Ranges,sizeof(Ranges));return out;}
static void ExFreePool(PVOID p){free(p);}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return++CancelChecks==CancelAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T n,ULONG flags){
 MapCalls++;assert(flags==PAGE_READONLY||flags==(PAGE_READONLY|PAGE_NOCACHE));if(MapCalls==FailMap)return NULL;
 if((ULONGLONG)a.QuadPart==0x81a00000&&n==0x40000){assert(flags==PAGE_READONLY);return Xbl;}
 if((ULONGLONG)a.QuadPart==0xa7605000&&n==0x8000){assert(flags==PAGE_READONLY);return Log;}
 if((ULONGLONG)a.QuadPart==0x146aa000&&n==0x1000){assert(flags==(PAGE_READONLY|PAGE_NOCACHE));return Imem;}
 assert(flags==(PAGE_READONLY|PAGE_NOCACHE));ULONGLONG off=(ULONGLONG)a.QuadPart-0x81d00000;
 assert((off==0&&n==0x3000)||(off==0x1ff000&&n==0x1000)||(off==0x4000&&n==0x80000)||(off==0x84000&&n==0x20000)||(off==0x19f000&&n==0x60000)||(off==0x1000&&n==0xb0000));
 return Smem+off;
}
static void MmUnmapIoSpace(PVOID p,SIZE_T n){assert(p&&n);Unmaps++;}
static void KeMemoryBarrier(void){__sync_synchronize();}
static SIZE_T RtlCompareMemory(const void*a,const void*b,SIZE_T n){const UCHAR*x=a,*y=b;SIZE_T i=0;for(;i<n&&x[i]==y[i];i++){}return i;}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-1000000);Time+=1000000;if(Mutation==1)Smem[0x1ff000]^=1;if(Mutation==2)Smem[0x84004]^=1;if(Mutation==3)Smem[0x40100]^=1;}
'''
main=r'''
static void put16(UCHAR*p,uint16_t v){p[0]=(UCHAR)v;p[1]=(UCHAR)(v>>8);}
static void put32(UCHAR*p,uint32_t v){for(int i=0;i<4;i++)p[i]=(UCHAR)(v>>(8*i));}
static void entry(UCHAR*t,ULONG i,ULONG off,ULONG n,uint16_t a,uint16_t b){UCHAR*p=t+32+48*i;put32(p,off);put32(p+4,n);put16(p+12,a);put16(p+14,b);put32(p+16,64);p=Smem+off;put32(p,0x54525024);put16(p+4,a);put16(p+6,b);put32(p+8,n);put32(p+12,32);put32(p+16,n);}
static G108_CAPTURE*Out;
static void Reset(void){memset(Out,0,sizeof(*Out));memset(Smem,0,sizeof(Smem));memset(Ranges,0,sizeof(Ranges));MapCalls=Unmaps=FailMap=CancelAt=CancelChecks=Mutation=NoRanges=0;G108Maps=G108Fault=G108Ready=0;FullOS=FirmwareMatch=1;Processors=8;Build=26300;Time=0;UCHAR*t=Smem+0x1ff000;put32(t,0x434f5424);put32(t+4,1);put32(t+8,2);entry(t,0,0x4000,0x80000,0xfffe,0xfffe);entry(t,1,0x84000,0x20000,0,2);}
int main(int argc,char**argv){unsigned cases=0;Out=calloc(1,sizeof(*Out));assert(Out);
 Reset();Capture(Out,(void*)1,123);assert(!Out->Code&&Out->CompleteMask==127&&Out->RegionCount==7&&MapCalls==14&&Unmaps==14&&Out->ReadBytes==Out->PayloadBytes&&Out->Nonce==123);cases++;
 for(unsigned i=1;i<=14;i++){Reset();FailMap=i;Capture(Out,(void*)1,123);assert(Out->Code&&MapCalls==i&&Unmaps==i-1&&G108Ready&&G108Fault);cases++;}
 for(unsigned i=1;i<=14;i++){Reset();CancelAt=i;Capture(Out,(void*)1,123);assert(Out->Code&&MapCalls==i-1&&Unmaps==MapCalls);cases++;}
 for(unsigned i=0;i<4;i++){Reset();if(i==0)FullOS=0;if(i==1)FirmwareMatch=0;if(i==2)Processors=1;if(i==3)Build=1;Capture(Out,(void*)1,123);assert(Out->Code==1001&&!MapCalls&&!Unmaps);cases++;}
 for(unsigned i=0;i<3;i++){Reset();Ranges[0].BaseAddress.QuadPart=(LONGLONG[]){0x81a00000,0x81d00000,0xa7605000}[i];Ranges[0].NumberOfBytes.QuadPart=4096;Capture(Out,(void*)1,123);assert(Out->Code==1002&&!MapCalls&&!Unmaps);cases++;}
 Reset();NoRanges=1;Capture(Out,(void*)1,123);assert(Out->Code==1002&&!MapCalls);cases++;
 Reset();Smem[0x1ff000]=0;Capture(Out,(void*)1,123);assert(Out->Code==2001&&MapCalls==5&&Unmaps==5);cases++;
 Reset();Smem[0x84004]=1;Capture(Out,(void*)1,123);assert(Out->Code==1006&&MapCalls==7&&Unmaps==7);cases++;
 for(unsigned i=1;i<=3;i++){Reset();Mutation=i;Capture(Out,(void*)1,123);assert(Out->Code==(i==1?1008u:i==2?1009u:0u)&&Unmaps==MapCalls&&MapCalls==14);cases++;}
 if(argc==2){Reset();FILE*f=fopen(argv[1],"rb");assert(f&&fread(Smem+0x1ff000,1,4096,f)==4096&&fgetc(f)==EOF);fclose(f);G108_PART parts[2];uint32_t n;assert(!G108Select(Smem+0x1ff000,4096,parts,&n)&&n==2);for(unsigned i=0;i<n;i++){UCHAR*p=Smem+parts[i].Offset;put32(p,0x54525024);put16(p+4,(uint16_t)parts[i].Host0);put16(p+6,(uint16_t)parts[i].Host1);put32(p+8,parts[i].Bytes);put32(p+12,32);put32(p+16,parts[i].Bytes);}Capture(Out,(void*)1,123);assert(!Out->Code&&Out->RegionCount==7&&MapCalls==Unmaps&&MapCalls==14);cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_functions\":true,\"OS_and_RAM_maps_and_time_modeled\":true,\"all_maps_read_only\":true,\"map_failure_and_cancellation_cleanup_verified\":true,\"native_operations\":0}\n",cases);free(Out);return 0;}
'''
path=o/'model.c';path.write_text(pre+'\n'.join(fn(n)for n in ['ReservedRam','Add','CopyRegion','Capture'])+main)
r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(path),'-o',str(o/'test')],capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test'),str(w.parent/'private/native-SMEM-TOC.bin')],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout);report['source_hashes']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g108_driver.c','g108_select.h','g108_protocol.h']}
(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(r.stdout)
