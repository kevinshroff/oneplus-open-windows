from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);w=Path(__file__).resolve().parent;s=(w/'g110_driver.c').read_text();m=re.search(r'^VOID G110Control\(',s,re.M);i=s.index('{',m.end())+1;d=1
while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
fn=s[m.start():i]
pre=r'''#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG,NTSTATUS;typedef uint64_t ULONG_PTR;typedef void*PVOID;typedef void*WDFREQUEST;typedef void*WDFQUEUE;
#define VOID void
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define NT_SUCCESS(s) ((s)>=0)
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_REQUEST (-1)
#define STATUS_INVALID_PARAMETER (-2)
#define STATUS_BUFFER_TOO_SMALL (-3)
#define STATUS_NOT_FOUND (-4)
#define STATUS_QUOTA_EXCEEDED (-5)
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define RtlCopyMemory memcpy
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g110_protocol.h"
static G110_CAPTURE Frozen,Response;static G110_CAPTURE*G110Frozen=&Frozen;static volatile LONG G110Attempts,G110Ready;static unsigned Calls,StatusCalls,Cases;
typedef struct{void*In,*Out;NTSTATUS InStatus,OutStatus,Completed;ULONG_PTR Information;}Request;
static LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG want){return __sync_val_compare_and_swap(p,want,v);}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST p,size_t n,void**out,void*z){Request*r=p;(void)z;assert(n==32);if(!r->InStatus)*out=r->In;return r->InStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST p,size_t n,void**out,void*z){Request*r=p;(void)z;assert(n==80||n==sizeof(G110_CAPTURE));if(!r->OutStatus)*out=r->Out;return r->OutStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST p,NTSTATUS s,ULONG_PTR n){Request*r=p;r->Completed=s;r->Information=n;}
static void Status(G110_STATUS*p){memset(p,0,sizeof(*p));p->Size=80;StatusCalls++;}
static void Capture(G110_CAPTURE*p,WDFREQUEST r,ULONGLONG nonce){assert(p==&Frozen&&r&&nonce);Calls++;p->Nonce=nonce;G110Ready=1;}
'''
main=r'''
static void Reset(void){memset(&Frozen,0,sizeof(Frozen));memset(&Response,0,sizeof(Response));G110Attempts=G110Ready=Calls=StatusCalls=0;}
int main(void){const ULONG codes[3]={G110_IOCTL_STATUS,G110_IOCTL_READ,G110_IOCTL_RESULT};
 for(unsigned at=0;at<3;at++)for(unsigned bad=0;bad<13;bad++){Reset();G110_REQUEST q={32,1,G110_MAGIC,at?123:0,0,0};size_t in=32,out=at?sizeof(Response):80;ULONG code=codes[at];if(bad==0)code=0;if(bad==1)q.Size--;if(bad==2)q.Version++;if(bad==3)q.Magic^=1;if(bad==4)q.Reserved=1;if(bad==5)in--;if(bad==6)in++;if(bad==7)out--;if(bad==8)out++;if(bad==9){if(!at)q.Nonce=1;else q.Nonce=0;}if(bad==10)q.Count=1;Request r={&q,&Response,0,0,0,0};if(bad==11)r.InStatus=-11;if(bad==12)r.OutStatus=-12;G110Control(0,&r,out,in,code);assert(r.Completed<0&&!r.Information&&!Calls&&!StatusCalls&&!G110Attempts);Cases++;}
 Reset();G110_REQUEST q={32,1,G110_MAGIC,123,1025,0};Request r={&q,&Response,0,0,0,0};G110Control(0,&r,sizeof(Response),32,G110_IOCTL_READ);assert(r.Completed<0&&!Calls);Cases++;
 Reset();q=(G110_REQUEST){32,1,G110_MAGIC,0,0,0};r=(Request){&q,&Response,0,0,0,0};G110Control(0,&r,80,32,G110_IOCTL_STATUS);assert(!r.Completed&&r.Information==80&&StatusCalls==1&&!Calls);Cases++;
 Reset();q=(G110_REQUEST){32,1,G110_MAGIC,123,0,0};memcpy(&Response,&q,sizeof(q));r=(Request){&Response,&Response,0,0,0,0};G110Control(0,&r,sizeof(Response),32,G110_IOCTL_READ);assert(!r.Completed&&r.Information==sizeof(Response)&&Calls==1&&Response.Nonce==123);Cases++;
 r=(Request){&q,&Response,0,0,0,0};G110Control(0,&r,sizeof(Response),32,G110_IOCTL_READ);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Calls==1);Cases++;
 q.Count=0;q.Nonce=124;r=(Request){&q,&Response,0,0,0,0};G110Control(0,&r,sizeof(Response),32,G110_IOCTL_RESULT);assert(r.Completed==STATUS_NOT_FOUND&&Calls==1);Cases++;
 q.Nonce=123;r=(Request){&q,&Response,0,0,0,0};G110Control(0,&r,sizeof(Response),32,G110_IOCTL_RESULT);assert(!r.Completed&&Calls==1&&Response.Nonce==123&&!memcmp(&Frozen,&Response,sizeof(Frozen)));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_dispatch_function\":true,\"overlapping_buffer_verified\":true,\"one_shot_and_nonce_verified\":true,\"WDF_and_capture_modeled\":true,\"native_operations\":0}\n",Cases);return 0;}
'''
f=a.output/'model.c';f.write_text(pre+fn+main);exe=a.output/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g110_driver.c','g110_protocol.h']};(a.output/'tests.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
