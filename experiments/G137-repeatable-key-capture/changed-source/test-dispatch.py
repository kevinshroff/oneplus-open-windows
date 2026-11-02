from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);w=Path(__file__).resolve().parent;s=(w/'g100_keys.c').read_text();m=re.search(r'^int G100KeysTryControl\(',s,re.M);i=s.index('{',m.end())+1;d=1
while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
fn=s[m.start():i]
pre=r'''#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "g99_core.h"
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG,NTSTATUS;typedef int64_t LONG64;typedef uint64_t ULONG_PTR;typedef void*PVOID;typedef unsigned char*PUCHAR;typedef void*WDFREQUEST;typedef void*WDFQUEUE;
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
#define STATUS_DEVICE_NOT_READY (-6)
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define RtlCopyMemory memcpy
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g99_protocol.h"
#include "g100_keys.h"
#include "g100_bus.h"
#include "g100_protocol.h"
#include "g137_protocol.h"
static G99_CAPTURE Frozen,Response;static G100_KEYS Keys;static unsigned Calls,StatusCalls,Cases,CaptureFault,BusPoison;
typedef struct{void*In,*Out;NTSTATUS InStatus,OutStatus,Completed;ULONG_PTR Information;}Request;
static LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG want){return __sync_val_compare_and_swap(p,want,v);}
static LONG InterlockedExchange(volatile LONG*p,LONG v){return __sync_lock_test_and_set(p,v);}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST p,size_t n,void**out,void*z){Request*r=p;(void)z;assert(n==32||n==G137_RETIRE_BYTES);if(!r->InStatus)*out=r->In;return r->InStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST p,size_t n,void**out,void*z){Request*r=p;(void)z;assert(n==56||n==64||n==80||n==sizeof(G99_CAPTURE));if(!r->OutStatus)*out=r->Out;return r->OutStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST p,NTSTATUS s,ULONG_PTR n){Request*r=p;r->Completed=s;r->Information=n;}
void G100BusStatus(G100_BUS_STATUS*p){memset(p,0,sizeof(*p));p->Size=56;p->Ready=1;p->Poisoned=BusPoison;}
static void Status(G100_KEYS*k,G99_STATUS*p){(void)k;memset(p,0,sizeof(*p));p->Size=80;StatusCalls++;}
static void Capture(G100_KEYS*k,G99_CAPTURE*p,WDFREQUEST r,ULONGLONG nonce,ULONG n){assert(p==&Frozen&&r&&nonce&&n>0&&n<=1024);Calls++;p->Nonce=nonce;p->Requested=n;k->Maps=5;k->Ready=1;if(CaptureFault){k->Fault=1;p->Result.Code=77;}}
'''
main=r'''
static void Reset(void){memset(&Frozen,0,sizeof(Frozen));memset(&Response,0,sizeof(Response));memset(&Keys,0,sizeof(Keys));Keys.Frozen=&Frozen;Calls=StatusCalls=CaptureFault=BusPoison=0;}
int main(void){const ULONG codes[4]={G99_IOCTL_STATUS,G99_IOCTL_SAMPLE,G99_IOCTL_RESULT,G100_IOCTL_BUS};
 for(unsigned at=0;at<4;at++)for(unsigned bad=0;bad<13;bad++){Reset();G99_REQUEST q={32,1,G99_MAGIC,(at==1||at==2)?123:0,at==1?1:0,0};size_t in=32,out=at==3?56:at?sizeof(Response):80;ULONG code=codes[at];if(bad==0)code=0;if(bad==1)q.Size--;if(bad==2)q.Version++;if(bad==3)q.Magic^=1;if(bad==4)q.Reserved=1;if(bad==5)in--;if(bad==6)in++;if(bad==7)out--;if(bad==8)out++;if(bad==9){if(at==0||at==3)q.Nonce=1;else q.Nonce=0;}if(bad==10){if(at==1)q.Count=0;else q.Count=1;}Request r={&q,&Response,0,0,0,0};if(bad==11)r.InStatus=-11;if(bad==12)r.OutStatus=-12;G99Control(0,&r,out,in,code);assert(r.Completed<0&&!r.Information&&!Calls&&!StatusCalls&&!Keys.Attempts);Cases++;}
 Reset();G99_REQUEST q={32,1,G99_MAGIC,123,1025,0};Request r={&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(r.Completed<0&&!Calls);Cases++;
 Reset();q=(G99_REQUEST){32,1,G99_MAGIC,0,0,0};r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,80,32,G99_IOCTL_STATUS);assert(!r.Completed&&r.Information==80&&StatusCalls==1&&!Calls);Cases++;
 Reset();q=(G99_REQUEST){32,1,G99_MAGIC,0,0,0};r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,56,32,G100_IOCTL_BUS);assert(!r.Completed&&r.Information==56&&!Calls&&!StatusCalls&&((G100_BUS_STATUS*)&Response)->Size==56);Cases++;
 Reset();q=(G99_REQUEST){32,1,G99_MAGIC,123,1,0};memcpy(&Response,&q,sizeof(q));r=(Request){&Response,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(!r.Completed&&r.Information==sizeof(Response)&&Calls==1&&Response.Nonce==123&&Response.Requested==1);Cases++;
 r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Calls==1);Cases++;
 q.Count=0;q.Nonce=124;r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_RESULT);assert(r.Completed==STATUS_NOT_FOUND&&Calls==1);Cases++;
 q.Nonce=123;r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_RESULT);assert(!r.Completed&&Calls==1&&Response.Nonce==123&&!memcmp(&Frozen,&Response,sizeof(Frozen)));Cases++;

 typedef struct{G99_REQUEST Header;G99_CAPTURE Capture;}Ack;
 static Ack ack;static G137_STATE state;static unsigned char shared[sizeof(Ack)];
 for(unsigned at=0;at<2;at++)for(unsigned bad=0;bad<13;bad++){
  Reset();q=(G99_REQUEST){32,1,G99_MAGIC,at?123:0,0,0};ack.Header=q;memset(&ack.Capture,0,sizeof(ack.Capture));
  size_t in=at?sizeof(ack):32,out=64;ULONG code=at?G137_IOCTL_RETIRE:G137_IOCTL_STATE;
  if(bad==0)q.Size--;if(bad==1)q.Version++;if(bad==2)q.Magic^=1;if(bad==3)q.Reserved=1;
  if(bad==4)in--;if(bad==5)in++;if(bad==6)out--;if(bad==7)out++;
  if(bad==8)q.Nonce=at?0:1;if(bad==9)q.Count=1;ack.Header=q;
  r=(Request){&ack,&state,0,0,0,0};if(bad==10)r.InStatus=-11;if(bad==11)r.OutStatus=-12;
  if(bad==12){if(at)BusPoison=1;else q.Count=1;ack.Header=q;}
  G99Control(0,&r,out,in,code);assert(r.Completed<0&&!r.Information&&!Calls&&!StatusCalls&&!Keys.Attempts&&!Keys.Ledger.Count);Cases++;
 }
 Reset();q=(G99_REQUEST){32,1,G99_MAGIC,0,0,0};r=(Request){&q,&state,0,0,0,0};G99Control(0,&r,64,32,G137_IOCTL_STATE);assert(!r.Completed&&state.Size==64&&!state.Phase&&!state.Captures&&!Calls&&!StatusCalls);Cases++;
 Reset();q=(G99_REQUEST){32,1,G99_MAGIC,123,1,0};r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(!r.Completed&&Keys.Ledger.Phase==G137_READY);ack.Header=(G99_REQUEST){32,1,G99_MAGIC,123,0,0};ack.Capture=Frozen;
 for(unsigned bad=0;bad<8;bad++){
  Ack save=ack;G137_LEDGER before=Keys.Ledger;
  if(bad<4)((unsigned char*)&ack.Capture)[bad==0?0:bad==1?80:bad==2?104:sizeof(Frozen)-1]^=1;
  if(bad==4)ack.Header.Nonce=124;if(bad==5)BusPoison=1;if(bad==6)Keys.Fault=1;
  r=(Request){&ack,&state,0,bad==7?-12:0,0,0};G99Control(0,&r,64,sizeof(ack),G137_IOCTL_RETIRE);
  assert(r.Completed<0&&!r.Information&&Keys.Attempts==1&&Keys.Ready==1&&Keys.Maps==5&&!memcmp(&before,&Keys.Ledger,sizeof(before)));ack=save;BusPoison=0;Keys.Fault=0;Cases++;
 }
 r=(Request){&ack,&state,0,0,0,0};G99Control(0,&r,64,sizeof(ack),G137_IOCTL_RETIRE);assert(!r.Completed&&r.Information==64&&state.Phase==G137_EMPTY&&state.Captures==1&&state.Retirements==1&&state.TotalMaps==5&&!Keys.Attempts&&!Keys.Ready&&!Keys.Maps&&Calls==1&&!memcmp(&Frozen,&ack.Capture,sizeof(Frozen)));Cases++;
 G137_LEDGER stable=Keys.Ledger;r=(Request){&ack,&state,0,0,0,0};G99Control(0,&r,64,sizeof(ack),G137_IOCTL_RETIRE);assert(!r.Completed&&!memcmp(&stable,&Keys.Ledger,sizeof(stable))&&Calls==1);Cases++;
 q=(G99_REQUEST){32,1,G99_MAGIC,123,1,0};r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(r.Completed<0&&!Keys.Attempts&&Calls==1);Cases++;
 q.Nonce=124;r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(!r.Completed&&Keys.Ledger.Count==2&&Keys.Ledger.TotalMaps==10&&Calls==2);Cases++;
 r=(Request){&ack,&state,0,0,0,0};G99Control(0,&r,64,sizeof(ack),G137_IOCTL_RETIRE);assert(r.Completed<0&&Keys.Ready==1&&Keys.Ledger.Phase==G137_READY&&Keys.Ledger.Retired==1);Cases++;
 ack.Header.Nonce=124;ack.Capture=Frozen;memcpy(shared,&ack,sizeof(ack));r=(Request){shared,shared,0,0,0,0};G99Control(0,&r,64,sizeof(ack),G137_IOCTL_RETIRE);assert(!r.Completed&&((G137_STATE*)shared)->Retirements==2&&!Keys.Ready&&!memcmp(&ack.Capture,&Frozen,sizeof(Frozen)));Cases++;
 Reset();CaptureFault=1;q=(G99_REQUEST){32,1,G99_MAGIC,123,1,0};r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(!r.Completed&&Keys.Fault&&Keys.Ledger.Phase==G137_FAULT);ack.Header=(G99_REQUEST){32,1,G99_MAGIC,123,0,0};ack.Capture=Frozen;r=(Request){&ack,&state,0,0,0,0};G99Control(0,&r,64,sizeof(ack),G137_IOCTL_RETIRE);assert(r.Completed<0&&Keys.Ready==1&&Keys.Attempts==1&&!Keys.Ledger.Retired);Cases++;
 Reset();BusPoison=1;q=(G99_REQUEST){32,1,G99_MAGIC,123,1,0};r=(Request){&q,&Response,0,0,0,0};G99Control(0,&r,sizeof(Response),32,G99_IOCTL_SAMPLE);assert(r.Completed<0&&!Calls&&!Keys.Attempts&&!Keys.Ledger.Count);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_dispatch_function\":true,\"overlapping_buffer_verified\":true,\"one_shot_and_nonce_verified\":true,\"WDF_and_capture_modeled\":true,\"native_operations\":0}\n",Cases);return 0;}
'''
f=a.output/'model.c';f.write_text(pre+fn+'\nstatic void G99Control(WDFQUEUE q,WDFREQUEST r,size_t o,size_t i,ULONG code){(void)q;if(!G100KeysTryControl(&Keys,r,o,i,code))WdfRequestCompleteWithInformation(r,STATUS_INVALID_DEVICE_REQUEST,0);}\n'+main);exe=a.output/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),str(w/'g137_capture.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g100_keys.c','g100_keys.h','g137_capture.c','g137_capture.h','g137_protocol.h','g99_protocol.h','g99_core.h']};(a.output/'tests.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
