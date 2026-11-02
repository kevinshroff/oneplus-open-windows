"""Run actual dispatch/lifecycle callbacks with modeled WDF/VHF services."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g51_driver.c').read_text()
def function(name):
 m=re.search(r'^(?:static )?(?:ULONG|VOID|NTSTATUS) '+name+r'\(',s,re.M);assert m,name;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{\n VHFHANDLE Handle;.*?\} G51_CONTEXT;',s,re.S).group()
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
#include "g51_protocol.h"
#include "g51_report.h"
typedef struct{UCHAR*reportBuffer;ULONG reportBufferLen;UCHAR reportId;}HID_XFER_PACKET,*PHID_XFER_PACKET;
typedef struct{void*In;void*Out;NTSTATUS InStatus,OutStatus,Completed;ULONG_PTR Information;}Request,*WDFREQUEST;
static LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG cmp){LONG old=*p;if(old==cmp)*p=v;return old;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
'''
stubs=r'''
static G51_CONTEXT C;static unsigned Submits,Deletes,Starts,Completions,Cases;static NTSTATUS SubmitReturn,StartReturn,AsyncStatus;static G51_STATUS Identity;
static G51_CONTEXT*G51Context(WDFDEVICE d){assert(d==(void*)1);return&C;}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){assert(q==(void*)2);return(void*)1;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==16);if(!r->InStatus)*p=r->In;return r->InStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==128);if(!r->OutStatus)*p=r->Out;return r->OutStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,ULONG_PTR n){r->Completed=s;r->Information=n;Completions++;}
static void Status(G51_CONTEXT*c,G51_STATUS*out){*out=Identity;out->D0=c->D0;out->Started=c->Started;out->EmptyAttempts=c->EmptyAttempts;out->EmptyAccepted=c->EmptyAccepted;out->LastSubmit=c->LastSubmit;}
static NTSTATUS VhfReadReportSubmit(VHFHANDLE h,PHID_XFER_PACKET p){assert(h==(void*)3&&p&&p->reportId==1&&p->reportBufferLen==64&&G51IsEmptyReport(p->reportBuffer,64));Submits++;return SubmitReturn;}
static NTSTATUS VhfStart(VHFHANDLE h){assert(h==(void*)3);Starts++;return StartReturn;}
static void VhfDelete(VHFHANDLE h,int wait){assert(h==(void*)3&&wait);Deletes++;}
static NTSTATUS VhfAsyncOperationComplete(VHFOPERATIONHANDLE h,NTSTATUS s){assert(h==(void*)4);AsyncStatus=s;return 0;}
static void Reset(void){memset(&C,0,sizeof(C));memset(&Identity,0,sizeof(Identity));C.Handle=(void*)3;C.D0=C.Started=1;Identity.FirmwareMatch=1;Identity.KernelBuild=26100;Identity.Processors=8;Submits=Deletes=Starts=Completions=0;SubmitReturn=StartReturn=0;}
'''
body='\n'.join(function(n)for n in['G51Feature','G51Control','G51D0Entry','G51D0Exit','G51IoInit','G51Cleanup'])
main=r'''
static void Call(ULONG code,size_t in,size_t out,G51_REQUEST*req,Request*r,G51_STATUS*response){memset(r,0,sizeof(*r));r->In=req;r->Out=response;G51Control((void*)2,r,out,in,code);assert(Completions);Cases++;}
int main(void){G51_REQUEST req={16,1,G51_MAGIC};G51_STATUS response;Request r;unsigned i;uint8_t f[3];HID_XFER_PACKET packet;
 Reset();Call(G51_IOCTL_STATUS,16,128,&req,&r,&response);assert(!r.Completed&&r.Information==128&&!Submits&&!C.EmptyAttempts);
 Reset();Call(G51_IOCTL_EMPTY,16,128,&req,&r,&response);assert(!r.Completed&&r.Information==128&&Submits==1&&C.EmptyAttempts==1&&C.EmptyAccepted==1&&!C.LastSubmit);
 Call(G51_IOCTL_EMPTY,16,128,&req,&r,&response);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Submits==1&&C.EmptyAttempts==1);
 assert(!G51D0Exit((void*)1,0)&&!C.D0&&!G51D0Entry((void*)1,0)&&C.D0&&C.Entries==C.Exits&&C.Entries==1);Cases++;
 Call(G51_IOCTL_EMPTY,16,128,&req,&r,&response);assert(r.Completed==STATUS_QUOTA_EXCEEDED&&Submits==1);
 Reset();SubmitReturn=STATUS_DEVICE_NOT_READY;Call(G51_IOCTL_EMPTY,16,128,&req,&r,&response);assert(!r.Completed&&C.EmptyAttempts==1&&!C.EmptyAccepted&&C.LastSubmit==STATUS_DEVICE_NOT_READY&&Submits==1);
 for(i=0;i<14;i++){
  G51_REQUEST q=req;ULONG code=G51_IOCTL_EMPTY;size_t in=16,out=128;Reset();
  if(i==0)code=0;if(i==1)in=15;if(i==2)in=17;if(i==3)q.Size=15;if(i==4)q.Version=2;if(i==5)q.Magic^=1;if(i==6)out=127;
  if(i==7)Identity.FirmwareMatch=0;if(i==8)Identity.Processors=7;if(i==9)Identity.KernelBuild=26101;if(i==10)Identity.Irql=2;if(i==11)C.D0=0;if(i==12)C.Started=0;if(i==13)C.Handle=NULL;
  Call(code,in,out,&q,&r,&response);assert(r.Completed<0&&!r.Information&&!Submits&&!C.EmptyAttempts);
 }
 for(i=0;i<2;i++){Reset();memset(&r,0,sizeof(r));r.In=&req;r.Out=&response;if(i)r.OutStatus=STATUS_BUFFER_TOO_SMALL;else r.InStatus=STATUS_INVALID_PARAMETER;G51Control((void*)2,&r,128,16,G51_IOCTL_EMPTY);assert(r.Completed<0&&!r.Information&&!Submits&&!C.EmptyAttempts);Cases++;}
 Reset();C.Started=0;assert(!G51IoInit((void*)1)&&C.Started&&Starts==1);G51Cleanup((void*)1);assert(!C.Handle&&!C.Started&&Deletes==1);G51Cleanup((void*)1);assert(Deletes==1);Cases++;
 Reset();C.Started=0;StartReturn=STATUS_DEVICE_NOT_READY;assert(G51IoInit((void*)1)==STATUS_DEVICE_NOT_READY&&!C.Started&&C.StartStatus==STATUS_DEVICE_NOT_READY);G51Cleanup((void*)1);assert(!C.Handle&&Deletes==1);Cases++;
 Reset();memset(&packet,0,sizeof(packet));packet.reportBuffer=f;packet.reportBufferLen=3;packet.reportId=2;memset(f,0xa5,sizeof(f));G51Feature(&C,(void*)4,NULL,&packet);assert(!AsyncStatus&&packet.reportBufferLen==2&&f[0]==2&&f[1]==10&&f[2]==0xa5&&C.Features==1);Cases++;
 for(i=0;i<3;i++){packet.reportBuffer=f;packet.reportBufferLen=i==0?1:3;packet.reportId=i==1?3:2;if(i==2)packet.reportBuffer=NULL;G51Feature(&C,(void*)4,NULL,&packet);assert(AsyncStatus==STATUS_NOT_SUPPORTED);Cases++;}
 G51Feature(&C,(void*)4,NULL,NULL);assert(AsyncStatus==STATUS_NOT_SUPPORTED);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_dispatch_and_lifecycle_callbacks\":true,\"one_zero_contact_submit_per_instance\":true,\"power_transition_does_not_reset_budget\":true,\"failed_submit_not_replayed\":true,\"synchronous_delete_once\":true,\"unqualified_identity_or_mapping_never_injects_contacts\":true}\n",Cases);return 0;}
'''
f=a.output/'driver-model.c';f.write_text(prefix+context+stubs+body+main);exe=a.output/'driver-model';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-fsanitize=address,undefined','-I',str(W),str(f),str(W/'g51_report.c'),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout)
assert 'WdfDriverInitNonPnpDriver'not in s and 'queue.PowerManaged=WdfTrue'in s and 'config.EvtVhfAsyncOperationGetFeature=G51Feature'in s
v.update(ASan_UBSan=True,driver_sha256=hashlib.sha256(s.encode()).hexdigest(),protocol_sha256=hashlib.sha256((W/'g51_protocol.h').read_bytes()).hexdigest(),native_operations=0,limits=['WDF/VHF/firmware APIs are modeled; actual Windows PnP, parser, locking and power behavior need native evidence.','No physical contact, report pump, rotation or panel calibration is qualified.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
