"""Actual capture, blank and dispatcher under explicit RAM/MMIO/WDF models."""
from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
s=(w/'g188_driver.c').read_text();body=s[s.index('typedef struct{PVOID Clock'):s.index('#include "lifecycle.inc"')]
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
typedef void VOID;typedef uint32_t ULONG,*PULONG;typedef uint64_t ULONGLONG;typedef int64_t LONGLONG;typedef int32_t LONG,NTSTATUS;typedef void*PVOID;typedef unsigned char UCHAR,*PUCHAR;typedef void*WDFREQUEST;typedef void*WDFQUEUE;typedef size_t SIZE_T;typedef uintptr_t ULONG_PTR;
typedef struct{LONGLONG QuadPart;}PHYSICAL_ADDRESS;typedef struct{PHYSICAL_ADDRESS BaseAddress,NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define MAXULONGLONG UINT64_MAX
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 512
#define PAGE_WRITECOMBINE 1024
#define PASSIVE_LEVEL 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_REQUEST (-1)
#define STATUS_INVALID_PARAMETER (-2)
#define STATUS_BUFFER_TOO_SMALL (-3)
#define STATUS_NOT_FOUND (-4)
#define STATUS_DEVICE_NOT_READY (-5)
#define STATUS_QUOTA_EXCEEDED (-6)
#define NT_SUCCESS(s) ((s)>=0)
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory(d,s,n) memcpy(d,s,n)
#define KeMemoryBarrier() ((void)0)
#include "g188_protocol.h"
static volatile LONG G188Attempts,G188Ready,G188Fault,G188Maps,G188Blank;static G188_CAPTURE Frozen,Output;static G188_CAPTURE*G188Frozen=&Frozen;
static ULONG Reg[6][1024],FB[G188_FB_MAP_BYTES/4],Maps,Unmaps,FailMap,CancelledAt,Checks,Writes,GateFailAt,GateChecks,Managed,NoRanges,FullOS,Firmware,Build,Processors;static ULONGLONG Time;static ULONG_PTR Information;static NTSTATUS Completion;static G188_REQUEST Request;static int Alias;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}static LONG InterlockedExchange(volatile LONG*p,LONG n){LONG v=*p;*p=n;return v;}static LONG InterlockedCompareExchange(volatile LONG*p,LONG n,LONG c){LONG v=*p;if(v==c)*p=n;return v;}
static ULONGLONG KeQueryInterruptTime(void){return++Time;}
static void Status(G188_STATUS*s){memset(s,0,sizeof(*s));s->Size=80;s->Version=1;s->Magic=G188_MAGIC;s->KernelBuild=Build;s->Processors=Processors;s->FirmwareBytes=576;s->FirmwareMatch=Firmware;s->MapCalls=G188Maps;s->Attempts=G188Attempts;s->Ready=G188Ready;s->Fault=G188Fault;}
static int FullWindows(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG flags){assert(!p&&!flags);if(NoRanges)return NULL;PPHYSICAL_MEMORY_RANGE r=calloc(2,sizeof(*r));assert(r);if(Managed){r[0].BaseAddress.QuadPart=Managed==1?G188_FB_PAGE:0xaf08000;r[0].NumberOfBytes.QuadPart=4096;}return r;}
static void ExFreePool(PVOID p){free(p);}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return++Checks==CancelledAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T bytes,ULONG flags){Maps++;if(Maps==FailMap)return NULL;if((ULONGLONG)a.QuadPart==G188_FB_PAGE){assert(bytes==G188_FB_MAP_BYTES&&(flags== (PAGE_READONLY|PAGE_WRITECOMBINE)||flags==(PAGE_READWRITE|PAGE_WRITECOMBINE)));return FB;}assert(bytes==4096&&flags==(PAGE_READONLY|PAGE_NOCACHE));if(a.QuadPart==0xaf08000)return Reg[0];if(a.QuadPart==0xaf09000)return Reg[1];for(unsigned i=0;i<4;i++)if(a.QuadPart==G188PipePages[i])return Reg[i+2];assert(!"Unknown map");return NULL;}
static void MmUnmapIoSpace(PVOID p,SIZE_T n){assert(p&&(n==4096||n==G188_FB_MAP_BYTES));Unmaps++;}
static ULONG ModelRead(PULONG p){if(p==Reg[0]){GateChecks++;if(GateChecks==GateFailAt)return 1;}return*p;}
static void ModelWrite(PULONG p,ULONG v){assert(v==0&&p>=FB+G188_FB_OFFSET/4&&p<FB+G188_FB_OFFSET/4+G188_WORDS);Writes++;*p=v;}
#define READ_REGISTER_ULONG(p) ModelRead(p)
#define WRITE_REGISTER_ULONG(p,v) ModelWrite(p,v)
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,PVOID*out,PVOID unused){assert(r==(void*)1&&n==32&&!unused);*out=Alias?(void*)&Output:(void*)&Request;return 0;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,PVOID*out,PVOID unused){assert(r==(void*)1&&n<=sizeof(Output)&&!unused);*out=&Output;memset(&Output,0,sizeof(Output));return 0;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,ULONG_PTR i){assert(r==(void*)1);Completion=s;Information=i;}
'''
main=r'''
static void Reset(void){memset(&Frozen,0,sizeof(Frozen));memset(&Output,0,sizeof(Output));memset(Reg,0,sizeof(Reg));memset(FB,0xa5,sizeof(FB));Maps=Unmaps=FailMap=CancelledAt=Checks=Writes=GateFailAt=GateChecks=Managed=NoRanges=Time=Alias=0;FullOS=Firmware=1;Build=26300;Processors=8;G188Attempts=G188Ready=G188Fault=G188Maps=G188Blank=0;Reg[0][0xc/4]=Reg[0][0xa4/4]=1;Reg[1][0]=0x80000000;Reg[1][1]=0x10000;for(unsigned i=0;i<4;i++)for(unsigned j=0;j<12;j++)Reg[i+2][G188Off[j]/4]=G188Expected[i][j];Request=(G188_REQUEST){32,1,G188_MAGIC,123,0,0};}
static void Run(int blank){Operate(&Frozen,(void*)1,123,blank);assert(Unmaps==Maps-(FailMap?1:0));assert(FB[G188_FB_OFFSET/4-1]==0xa5a5a5a5&&FB[G188_FB_OFFSET/4+G188_WORDS]==0xa5a5a5a5);}
int main(int argc,char**argv){unsigned cases=0;Reset();Run(0);assert(!Frozen.Header.Code&&Frozen.Header.ReadWords==G188_WORDS&&!Writes);for(unsigned i=0;i<G188_WORDS;i++)assert(Frozen.Pixels[i]==0xa5a5a5a5);cases++;if(argc==2){FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&Frozen,1,sizeof(Frozen),f)==sizeof(Frozen));fclose(f);}Run(1);assert(!Frozen.Header.Code&&Frozen.Header.BlankVerified&&Frozen.Header.WrittenWords==G188_WORDS&&Frozen.Header.VerifiedZero==G188_WORDS&&Writes==G188_WORDS);for(unsigned i=0;i<G188_WORDS;i++)assert(!FB[G188_FB_OFFSET/4+i]&&Frozen.Pixels[i]==0xa5a5a5a5);cases++;
 for(unsigned blank=0;blank<2;blank++)for(unsigned i=1;i<=7;i++){Reset();FailMap=i;Run(blank);assert(Frozen.Header.Code==1005&&!Writes);cases++;}
 for(unsigned i=0;i<4;i++)for(unsigned j=0;j<12;j++){Reset();Reg[i+2][G188Off[j]/4]^=1;Run(1);assert(Frozen.Header.Code==2003&&!Writes&&Maps==6);cases++;}
 for(unsigned blank=0;blank<2;blank++)for(unsigned i=0;i<3;i++){Reset();CancelledAt=i==0?1:i==1?1200:2484;Run(blank);assert(Frozen.Header.Code==1004&&!Frozen.Header.BlankVerified&&Frozen.Header.WrittenWords==(blank?(CancelledAt-1)*G188_WIDTH:0));cases++;}
 for(unsigned i=0;i<3;i++){Reset();if(i==0)NoRanges=1;else Managed=i;Run(1);assert(Frozen.Header.Code==1002&&!Maps&&!Writes);cases++;}
 for(unsigned i=0;i<4;i++){Reset();if(i==0)FullOS=0;if(i==1)Firmware=0;if(i==2)Build=1;if(i==3)Processors=1;Run(1);assert(Frozen.Header.Code==1001&&!Maps&&!Writes);cases++;}
 for(unsigned i=0;i<3;i++){Reset();GateFailAt=i==0?1:i==1?160:2000;Run(1);assert(Frozen.Header.Code&&!Frozen.Header.BlankVerified);cases++;}
 Reset();Alias=1;memcpy(&Output,&Request,32);G188Control(NULL,(void*)1,sizeof(Output),32,G188_IOCTL_READ);assert(!Completion&&Information==sizeof(Output)&&Frozen.Header.ReadWords==G188_WORDS&&!Writes&&G188Attempts==1);cases++;
 memcpy(&Output,&Request,32);G188Control(NULL,(void*)1,sizeof(G188_HEADER),32,G188_IOCTL_BLANK);assert(!Completion&&Information==136&&Frozen.Header.BlankVerified&&Writes==G188_WORDS);cases++;
 Alias=0;ULONG maps=Maps,writes=Writes;G188Control(NULL,(void*)1,sizeof(G188_HEADER),32,G188_IOCTL_BLANK);assert(Completion==STATUS_QUOTA_EXCEEDED&&!Information&&Maps==maps&&Writes==writes);cases++;
 Request.Nonce=999;G188Control(NULL,(void*)1,sizeof(Output),32,G188_IOCTL_RESULT);assert(Completion==STATUS_NOT_FOUND&&Maps==maps);cases++;Request.Nonce=123;G188Control(NULL,(void*)1,sizeof(Output),32,G188_IOCTL_RESULT);assert(!Completion&&Information==sizeof(Output)&&Maps==maps&&Writes==writes);cases++;
 Reset();G188Control(NULL,(void*)1,136,32,G188_IOCTL_BLANK);assert(Completion==STATUS_DEVICE_NOT_READY&&!Maps&&!Writes);cases++;
 for(unsigned i=0;i<6;i++){Reset();if(i==0)Request.Size++;if(i==1)Request.Version++;if(i==2)Request.Magic++;if(i==3)Request.Nonce=0;if(i==4)Request.Count++;if(i==5)Request.Reserved++;G188Control(NULL,(void*)1,sizeof(Output),32,G188_IOCTL_READ);assert(Completion==STATUS_INVALID_PARAMETER&&!Maps&&!Writes);cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_blank_dispatch\":true,\"OS_WDF_RAM_and_MMIO_modeled\":true,\"full_2772144_pixel_bounds_and_preserved_backup\":true,\"native_operations\":0}\n",cases);return 0;
}
'''
src=o/'model.c';src.write_text(pre+body+main);r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(src),'-o',str(o/'test')],text=True,capture_output=True);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test'),str(o/'fixture.bin')],text=True,capture_output=True);assert not r.returncode,(r.stdout,r.stderr);v=json.loads(r.stdout);v['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g188_driver.c','g188_protocol.h','g188_plan.h']};(o/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(r.stdout)
