"""Run actual dispatch/lifecycle callbacks with modeled WDF/VHF services."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g55_driver.c').read_text()
def function(name):
 m=re.search(r'^(?:static )?(?:ULONG|VOID|NTSTATUS|int|uint16_t) '+name+r'\(',s,re.M);assert m,name;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{\n VHFHANDLE Handle;.*?\} G55_CONTEXT;',s,re.S).group()
prefix=r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;typedef int32_t LONG,NTSTATUS;typedef int64_t LONG64;typedef uintptr_t ULONG_PTR;typedef void VOID,*PVOID,*WDFDEVICE,*WDFQUEUE,*WDFOBJECT,*VHFHANDLE,*VHFOPERATIONHANDLE;typedef int WDF_POWER_DEVICE_STATE;
typedef struct{uint32_t a;uint16_t b,c;uint8_t d[8];}GUID;
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define PASSIVE_LEVEL 0
#define TRUE 1
#define FALSE 0
#define KernelMode 0
typedef struct{int64_t QuadPart;}LARGE_INTEGER;typedef uint8_t*PUCHAR;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_QUOTA_EXCEEDED ((NTSTATUS)0xc0000044)
#define STATUS_DATA_ERROR ((NTSTATUS)0xc000003e)
#define NT_SUCCESS(s) ((s)>=0)
#define RtlZeroMemory(p,n) memset(p,0,n)
#include "g55_protocol.h"
#include "g55_report.h"
#include "g55_replay.h"
typedef struct{UCHAR*reportBuffer;ULONG reportBufferLen;UCHAR reportId;}HID_XFER_PACKET,*PHID_XFER_PACKET;
typedef struct{void*In;void*Out;NTSTATUS InStatus,OutStatus,Completed;ULONG_PTR Information;}Request,*WDFREQUEST;
static LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG cmp){LONG old=*p;if(old==cmp)*p=v;return old;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
'''
stubs=r'''
static G55_CONTEXT C;static unsigned Submits,Deletes,Starts,Completions,Cases;static NTSTATUS SubmitReturn,StartReturn,AsyncStatus;static unsigned FailAt,Waits;static uint64_t Clock;static G55_STATUS Identity;
static G55_CONTEXT*G55Context(WDFDEVICE d){assert(d==(void*)1);return&C;}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){assert(q==(void*)2);return(void*)1;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==16);if(!r->InStatus)*p=r->In;return r->InStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==160);if(!r->OutStatus)*p=r->Out;return r->OutStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,ULONG_PTR n){r->Completed=s;r->Information=n;Completions++;}
static void Status(G55_CONTEXT*c,G55_STATUS*out){*out=Identity;out->D0=c->D0;out->Started=c->Started;out->ReplayAttempts=c->ReplayAttempts;out->ReplayAccepted=c->ReplayAccepted;out->LastSubmit=c->LastSubmit;out->ReplayComplete=c->Replay.Complete;out->ReplayError=c->Replay.Error;out->AcceptedMask=c->AcceptedState.Mask;out->AcceptedGeneration=c->AcceptedState.Generation;out->CleanupAttempted=c->Replay.CleanupAttempted;out->CleanupAccepted=c->Replay.CleanupAccepted;out->ReplaySubmitted=c->Replay.Submitted;}
static NTSTATUS VhfReadReportSubmit(VHFHANDLE h,PHID_XFER_PACKET p){assert(h==(void*)3&&p&&p->reportId==1&&p->reportBufferLen==64&&p->reportBuffer[0]==1&&p->reportBuffer[63]==1);Submits++;return Submits==FailAt?STATUS_DEVICE_NOT_READY:SubmitReturn;}
static NTSTATUS VhfStart(VHFHANDLE h){assert(h==(void*)3);Starts++;return StartReturn;}
static void VhfDelete(VHFHANDLE h,int wait){assert(h==(void*)3&&wait);Deletes++;}
static NTSTATUS VhfAsyncOperationComplete(VHFOPERATIONHANDLE h,NTSTATUS s){assert(h==(void*)4);AsyncStatus=s;return 0;}
static void Reset(void){memset(&C,0,sizeof(C));memset(&Identity,0,sizeof(Identity));C.Handle=(void*)3;C.D0=C.Started=1;Identity.FirmwareMatch=1;Identity.KernelBuild=26100;Identity.Processors=8;Submits=Deletes=Starts=Completions=0;SubmitReturn=StartReturn=0;FailAt=Waits=0;Clock=0;}
static NTSTATUS KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*p){assert(mode==0&&alert==0&&p->QuadPart==-250000);Waits++;Clock+=250000;return 0;}
static uint64_t KeQueryInterruptTime(void){return Clock;}
'''
body='\n'.join(function(n)for n in['Counter','G55Submit','G55Wait','G55Scan','G55Feature','G55Control','G55D0Entry','G55D0Exit','G55IoInit','G55Cleanup'])
main=r'''
static void Call(ULONG code,size_t in,size_t out,G55_REQUEST*req,Request*r,G55_STATUS*response){memset(r,0,sizeof(*r));r->In=req;r->Out=response;G55Control((void*)2,r,out,in,code);assert(Completions);Cases++;}
int main(void){G55_REQUEST req={16,1,G55_MAGIC};G55_STATUS response;Request r;unsigned i;uint8_t f[3];HID_XFER_PACKET packet;
 Reset();Call(G55_IOCTL_STATUS,16,160,&req,&r,&response);assert(!r.Completed&&r.Information==160&&!Submits&&!C.ReplayAttempts);
 Reset();Call(G55_IOCTL_REPLAY,16,160,&req,&r,&response);assert(!r.Completed&&r.Information==160&&Submits==4&&Waits==3&&C.ReplayAttempts==1&&C.ReplayAccepted==4&&!C.LastSubmit&&response.ReplayComplete&&!response.ReplayError&&!response.AcceptedMask&&response.AcceptedGeneration==4);
 Call(G55_IOCTL_REPLAY,16,160,&req,&r,&response);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Submits==4&&C.ReplayAttempts==1);
 assert(!G55D0Exit((void*)1,0)&&!C.D0&&!G55D0Entry((void*)1,0)&&C.D0&&C.Entries==C.Exits&&C.Entries==1);Cases++;
 Call(G55_IOCTL_REPLAY,16,160,&req,&r,&response);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Submits==4);
 for(i=1;i<=4;i++){
  Reset();FailAt=i;Call(G55_IOCTL_REPLAY,16,160,&req,&r,&response);assert(!r.Completed&&!C.Replay.Complete&&C.Replay.Error==2&&C.ReplayAttempts==1&&!C.AcceptedState.Mask);
  assert(Submits==(i==1?1:i+1)&&C.Replay.CleanupAttempted==(i>1)&&C.Replay.CleanupAccepted==(i>1));unsigned old=Submits;
  Call(G55_IOCTL_REPLAY,16,160,&req,&r,&response);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Submits==old);
 }
 Reset();SubmitReturn=STATUS_DEVICE_NOT_READY;Call(G55_IOCTL_REPLAY,16,160,&req,&r,&response);assert(!r.Completed&&C.ReplayAttempts==1&&!C.ReplayAccepted&&C.LastSubmit==STATUS_DEVICE_NOT_READY&&Submits==1&&!C.AcceptedState.Mask);
 for(i=0;i<14;i++){
  G55_REQUEST q=req;ULONG code=G55_IOCTL_REPLAY;size_t in=16,out=160;Reset();
  if(i==0)code=0;if(i==1)in=15;if(i==2)in=17;if(i==3)q.Size=15;if(i==4)q.Version=2;if(i==5)q.Magic^=1;if(i==6)out=159;
  if(i==7)Identity.FirmwareMatch=0;if(i==8)Identity.Processors=7;if(i==9)Identity.KernelBuild=26101;if(i==10)Identity.Irql=2;if(i==11)C.D0=0;if(i==12)C.Started=0;if(i==13)C.Handle=NULL;
  Call(code,in,out,&q,&r,&response);assert(r.Completed<0&&!r.Information&&!Submits&&!C.ReplayAttempts);
 }
 for(i=0;i<2;i++){Reset();memset(&r,0,sizeof(r));r.In=&req;r.Out=&response;if(i)r.OutStatus=STATUS_BUFFER_TOO_SMALL;else r.InStatus=STATUS_INVALID_PARAMETER;G55Control((void*)2,&r,160,16,G55_IOCTL_REPLAY);assert(r.Completed<0&&!r.Information&&!Submits&&!C.ReplayAttempts);Cases++;}
 Reset();C.Started=0;assert(!G55IoInit((void*)1)&&C.Started&&Starts==1);G55Cleanup((void*)1);assert(!C.Handle&&!C.Started&&Deletes==1);G55Cleanup((void*)1);assert(Deletes==1);Cases++;
 Reset();C.Started=0;StartReturn=STATUS_DEVICE_NOT_READY;assert(G55IoInit((void*)1)==STATUS_DEVICE_NOT_READY&&!C.Started&&C.StartStatus==STATUS_DEVICE_NOT_READY);G55Cleanup((void*)1);assert(!C.Handle&&Deletes==1);Cases++;
 Reset();memset(&packet,0,sizeof(packet));packet.reportBuffer=f;packet.reportBufferLen=3;packet.reportId=2;memset(f,0xa5,sizeof(f));G55Feature(&C,(void*)4,NULL,&packet);assert(!AsyncStatus&&packet.reportBufferLen==2&&f[0]==2&&f[1]==10&&f[2]==0xa5&&C.Features==1);Cases++;
 for(i=0;i<3;i++){packet.reportBuffer=f;packet.reportBufferLen=i==0?1:3;packet.reportId=i==1?3:2;if(i==2)packet.reportBuffer=NULL;G55Feature(&C,(void*)4,NULL,&packet);assert(AsyncStatus==STATUS_NOT_SUPPORTED);Cases++;}
 G55Feature(&C,(void*)4,NULL,NULL);assert(AsyncStatus==STATUS_NOT_SUPPORTED);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_dispatch_and_lifecycle_callbacks\":true,\"one_replay_per_instance\":true,\"power_transition_does_not_reset_budget\":true,\"failed_replay_not_restarted\":true,\"synchronous_delete_once\":true,\"identity_and_request_guards_before_injection\":true}\n",Cases);return 0;}

'''
f=a.output/'driver-model.c';f.write_text(prefix+context+stubs+body+main);exe=a.output/'driver-model';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-fsanitize=address,undefined','-I',str(W),str(f),*[str(W/n)for n in ['g55_report.c','g55_raw.c','g55_lifecycle.c','g55_replay.c']],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout)
assert 'WdfDriverInitNonPnpDriver'not in s and 'queue.PowerManaged=WdfTrue'in s and 'config.EvtVhfAsyncOperationGetFeature=G55Feature'in s
v.update(ASan_UBSan=True,driver_sha256=hashlib.sha256(s.encode()).hexdigest(),protocol_sha256=hashlib.sha256((W/'g55_protocol.h').read_bytes()).hexdigest(),native_operations=0,limits=['WDF/VHF/firmware APIs are modeled; actual Windows PnP, parser, locking and power behavior need native evidence.','No native consumer delivery or continuous live hardware input is qualified.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
