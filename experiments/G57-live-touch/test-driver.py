"""Actual G57 root callbacks, actual input core; modeled WDF/VHF/hardware."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g57_driver.c').read_text()
def function(name):
 m=re.search(r'^(?:static )?(?:ULONG|VOID|NTSTATUS|int|uint16_t) '+name+r'\(',s,re.M);assert m,name;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
prefix='\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <assert.h>\n#include <stddef.h>\ntypedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;typedef int32_t LONG,NTSTATUS;typedef int64_t LONG64;typedef uintptr_t ULONG_PTR;typedef void VOID,*PVOID,*WDFDEVICE,*WDFQUEUE,*WDFOBJECT,*VHFHANDLE,*VHFOPERATIONHANDLE;typedef int WDF_POWER_DEVICE_STATE;\ntypedef struct{uint32_t a;uint16_t b,c;uint8_t d[8];}GUID;\n#define FILE_DEVICE_UNKNOWN 0x22\n#define METHOD_BUFFERED 0\n#define FILE_READ_ACCESS 1\n#define FILE_WRITE_ACCESS 2\n#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))\n#define C_ASSERT(x) _Static_assert(x,#x)\n#define FIELD_OFFSET(t,f) offsetof(t,f)\n#define UNREFERENCED_PARAMETER(x) ((void)(x))\n#define PASSIVE_LEVEL 0\n#define TRUE 1\n#define FALSE 0\n#define KernelMode 0\ntypedef struct{int64_t QuadPart;}LARGE_INTEGER;typedef uint8_t*PUCHAR;\n#define STATUS_SUCCESS ((NTSTATUS)0)\n#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)\n#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)\n#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)\n#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)\n#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)\n#define STATUS_QUOTA_EXCEEDED ((NTSTATUS)0xc0000044)\n#define STATUS_DATA_ERROR ((NTSTATUS)0xc000003e)\n#define NT_SUCCESS(s) ((s)>=0)\n#define RtlZeroMemory(p,n) memset(p,0,n)\n#include "g55_protocol.h"\n#include "g55_report.h"\n#include "g55_replay.h"\ntypedef struct{UCHAR*reportBuffer;ULONG reportBufferLen;UCHAR reportId;}HID_XFER_PACKET,*PHID_XFER_PACKET;\ntypedef struct{void*In;void*Out;NTSTATUS InStatus,OutStatus,Completed;ULONG_PTR Information;}Request,*WDFREQUEST;\nstatic LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG cmp){LONG old=*p;if(old==cmp)*p=v;return old;}\nstatic LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}\nstatic LONG InterlockedIncrement(volatile LONG*p){return++*p;}\n'
prefix=prefix.replace('#include "g55_protocol.h"\n#include "g55_report.h"\n#include "g55_replay.h"','#include "g57hid_protocol.h"\n#include "g57hid_report.h"\n#include "g57_input.h"\n#include "g57_hwapi.h"\n#include "test-fixtures.h"')
prefix=prefix.replace('typedef uintptr_t ULONG_PTR;','typedef uintptr_t ULONG_PTR;typedef size_t SIZE_T;')
context=re.search(r'typedef struct \{\n VHFHANDLE Handle;.*?\} G57HID_CONTEXT;',s,re.S).group()
stubs=r'''
static G57HID_CONTEXT C;static unsigned Submits,Deletes,Starts,Completions,Cases,HWQueries,HWCalls,HWUsed,Scenario;static NTSTATUS SubmitReturn,StartReturn,AsyncStatus;static unsigned FailAt;static G57HID_STATUS Identity;
static G57HID_CONTEXT*G57HIDContext(WDFDEVICE d){assert(d==(void*)1);return&C;}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){assert(q==(void*)2);return(void*)1;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==16);if(!r->InStatus)*p=r->In;return r->InStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==160||n==80||n==288||n==1728||n==959896);if(!r->OutStatus)*p=r->Out;return r->OutStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,ULONG_PTR n){r->Completed=s;r->Information=n;Completions++;}
static void Status(G57HID_CONTEXT*c,G57HID_STATUS*out){*out=Identity;out->D0=c->D0;out->Started=c->Started;out->LiveAttempts=c->LiveAttempts;out->ReportsAccepted=c->Live.SubmitAccepted;out->LiveComplete=c->LiveComplete;out->LiveError=c->LastHardwareCode?c->LastHardwareCode:c->Live.Error;out->AcceptedMask=c->Live.Accepted.Mask;out->AcceptedGeneration=c->Live.Accepted.Generation;out->StopAttempts=c->Live.StopAttempts;out->StopAccepted=c->Live.StopAccepted;out->ReportsSubmitted=c->Live.SubmitAttempts;}
static NTSTATUS VhfReadReportSubmit(VHFHANDLE h,PHID_XFER_PACKET p){assert(h==(void*)3&&p&&p->reportId==1&&p->reportBufferLen==64&&p->reportBuffer[0]==1&&p->reportBuffer[63]==1);Submits++;return Submits==FailAt?STATUS_DEVICE_NOT_READY:SubmitReturn;}
static NTSTATUS VhfStart(VHFHANDLE h){assert(h==(void*)3);Starts++;return StartReturn;}
static void VhfDelete(VHFHANDLE h,int wait){assert(h==(void*)3&&wait);Deletes++;}
static NTSTATUS VhfAsyncOperationComplete(VHFOPERATIONHANDLE h,NTSTATUS status){assert(h==(void*)4);AsyncStatus=status;return 0;}
static void Reset(void){memset(&C,0,sizeof(C));memset(&Identity,0,sizeof(Identity));C.Handle=(void*)3;C.D0=C.Started=1;Identity.FirmwareMatch=1;Identity.KernelBuild=26100;Identity.Processors=8;Submits=Deletes=Starts=Completions=HWQueries=HWCalls=HWUsed=Scenario=0;SubmitReturn=StartReturn=0;FailAt=0;}
uint64_t G57HardwareTimeUs(void){return 123456789;}
void G57HardwareStatus(G57_STATUS*out){memset(out,0,sizeof(*out));HWQueries++;}
NTSTATUS G57HardwareSnapshot(G57_SNAPSHOT*out){memset(out,0,sizeof(*out));HWQueries++;return 0;}
void G57HardwarePmic(G57_PMIC*out){memset(out,0,sizeof(*out));HWQueries++;}
void G57HardwareTrial(G57_TRIAL*out,const G57_STREAM_IO*io){
 memset(out,0,sizeof(*out));HWCalls++;assert(io&&io->Stage&&io->Publish);
 if(HWUsed++){out->Trial.Power.Code=1002;return;}out->Attempt=1;
 out->Trial.Power.Restored=out->FixedRegistersUnchanged=out->Trial.Touch.Restored=1;out->Trial.Touch.Poll.Limit=out->Trial.Touch.Poll.Cycles=100;
 if(Scenario==1){out->Trial.Power.Code=1003;return;}
 unsigned n=Scenario==2?1:4;
 for(unsigned i=0;i<n;i++){
  if(!io->Stage(io->Context,G57TESTReplayRaw[i],26,10000+i*10000)){out->Trial.Power.Code=7;break;}
  if(!io->Publish(io->Context,G57TESTReplayRaw[i],26)){out->Trial.Power.Code=8;break;}
 }
}
'''
body='\n'.join(function(n)for n in ['Counter','G57HIDSubmit','G57HIDStage','G57HIDPublish','G57HIDFeature','G57HIDControl','G57HIDD0Entry','G57HIDD0Exit','G57HIDIoInit','G57HIDCleanup'])
main=r'''
static G57_TRIAL Response;
static void Call(ULONG code,size_t in,size_t out,G57HID_REQUEST*req,Request*r){memset(r,0,sizeof(*r));r->In=req;r->Out=&Response;G57HIDControl((void*)2,r,out,in,code);assert(Completions);Cases++;}
int main(void){G57HID_REQUEST hw={16,1,G57_MAGIC},hid={16,1,G57HID_MAGIC};Request r;unsigned i;uint8_t f[3];HID_XFER_PACKET packet;
 const ULONG codes[5]={G57HID_IOCTL_STATUS,G57_IOCTL_STATUS,G57_IOCTL_SNAPSHOT,G57_IOCTL_PMIC,G57_IOCTL_POWER};const size_t sizes[5]={160,80,288,1728,959896};
 for(unsigned c=0;c<5;c++){
  Reset();Call(codes[c],16,sizes[c],c?&hw:&hid,&r);assert(!r.Completed&&r.Information==sizes[c]);if(c<4)assert(!HWCalls&&!Submits);
  for(unsigned bad=0;bad<9;bad++){
   Reset();G57HID_REQUEST req=c?hw:hid;ULONG code=codes[c];size_t in=16,out=sizes[c];
   if(bad==0)code=0x22e404;if(bad==1)in=15;if(bad==2)in=17;if(bad==3)req.Size=15;if(bad==4)req.Version=2;if(bad==5)req.Magic^=1;if(bad==6)req.Magic=c?G57HID_MAGIC:G57_MAGIC;if(bad==7)out--;if(bad==8)code=0;
   Call(code,in,out,&req,&r);assert(r.Completed<0&&!r.Information&&!HWCalls&&!HWQueries&&!Submits&&!C.LiveAttempts);
  }
 }
 Reset();Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(!r.Completed&&HWCalls==1&&Submits==4&&C.LiveAttempts==1&&C.LiveComplete&&!C.Live.Error&&!C.Live.Accepted.Mask&&C.Live.Accepted.Generation==4&&C.Live.StopAttempts==1&&!C.Live.StopAccepted);
 Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(!r.Completed&&Response.Trial.Power.Code==1002&&C.LiveAttempts==1&&C.LiveComplete&&Submits==4);
 assert(!G57HIDD0Exit((void*)1,0)&&!C.D0&&!G57HIDD0Entry((void*)1,0)&&C.D0&&C.Entries==1&&C.Exits==1);Cases++;
 Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(Response.Trial.Power.Code==1002&&Submits==4&&C.LiveAttempts==1);
 for(i=0;i<7;i++){
  Reset();if(i==0)Identity.FirmwareMatch=0;if(i==1)Identity.Processors=7;if(i==2)Identity.KernelBuild=26101;if(i==3)Identity.Irql=2;if(i==4)C.D0=0;if(i==5)C.Started=0;if(i==6)C.Handle=NULL;
  Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(r.Completed<0&&!r.Information&&!HWCalls&&!Submits&&!C.LiveAttempts);
 }
 for(i=1;i<=4;i++){
  Reset();FailAt=i;Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(!r.Completed&&!C.LiveComplete&&C.LiveAttempts==1&&!C.Live.Accepted.Mask&&C.Live.Error==5&&C.LastHardwareCode==8&&C.Live.StopAttempts==1);assert(Submits==(i==1?1:i+1));
 }
 Reset();Scenario=1;Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(!r.Completed&&C.LiveAttempts==1&&!C.LiveComplete&&C.Live.StopAttempts==1&&!Submits&&C.LastHardwareCode==1003);
 Reset();Scenario=2;Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(C.LiveComplete&&Submits==2&&C.Live.StopAccepted==1&&!C.Live.Accepted.Mask);
 Reset();Scenario=2;FailAt=2;Call(G57_IOCTL_POWER,16,sizeof(Response),&hw,&r);assert(!C.LiveComplete&&C.Live.StopAttempts==1&&!C.Live.StopAccepted&&C.Live.Error==8&&C.Live.Accepted.Mask==1&&Submits==2);
 for(i=0;i<2;i++){Reset();memset(&r,0,sizeof(r));r.In=&hw;r.Out=&Response;if(i)r.OutStatus=STATUS_BUFFER_TOO_SMALL;else r.InStatus=STATUS_INVALID_PARAMETER;G57HIDControl((void*)2,&r,sizeof(Response),16,G57_IOCTL_POWER);assert(r.Completed<0&&!r.Information&&!HWCalls&&!Submits);Cases++;}
 Reset();C.Started=0;assert(!G57HIDIoInit((void*)1)&&C.Started&&Starts==1);G57HIDCleanup((void*)1);assert(!C.Handle&&!C.Started&&Deletes==1);G57HIDCleanup((void*)1);assert(Deletes==1);Cases++;
 Reset();C.Started=0;StartReturn=STATUS_DEVICE_NOT_READY;assert(G57HIDIoInit((void*)1)==STATUS_DEVICE_NOT_READY&&!C.Started&&C.StartStatus==STATUS_DEVICE_NOT_READY);G57HIDCleanup((void*)1);assert(!C.Handle&&Deletes==1);Cases++;
 Reset();memset(&packet,0,sizeof(packet));packet.reportBuffer=f;packet.reportBufferLen=3;packet.reportId=2;memset(f,0xa5,sizeof(f));G57HIDFeature(&C,(void*)4,NULL,&packet);assert(!AsyncStatus&&packet.reportBufferLen==2&&f[0]==2&&f[1]==10&&f[2]==0xa5);Cases++;
 for(i=0;i<3;i++){packet.reportBuffer=f;packet.reportBufferLen=i==0?1:3;packet.reportId=i==1?3:2;if(i==2)packet.reportBuffer=NULL;G57HIDFeature(&C,(void*)4,NULL,&packet);assert(AsyncStatus==STATUS_NOT_SUPPORTED);Cases++;}
 G57HIDFeature(&C,(void*)4,NULL,NULL);assert(AsyncStatus==STATUS_NOT_SUPPORTED);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_root_dispatch_callbacks_and_input_core\":true,\"hardware_entry_and_WDF_VHF_services_modeled\":true,\"no_replay_IOCTL\":true,\"cross_magic_and_all5_output_bounds_guarded\":true,\"identity_before_hardware_call\":true,\"synchronous_delete_once\":true}\n",Cases);return 0;}
'''
f=a.output/'driver-model.c';f.write_text(prefix+context+stubs+body+main);exe=a.output/'driver-model';names=['g57hid_report.c','g57_report.c','g57hid_lifecycle.c','g57_input.c'];initial={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names+['g57_driver.c','g57hid_protocol.h','g57_protocol.h','g57_hwapi.h']}
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-fsanitize=address,undefined','-I',str(W),'-I',str(W/'private/inputs'if(W/'private/inputs').is_dir()else W/'inputs'),str(f),*[str(W/n)for n in names],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout)
assert all(hashlib.sha256((W/n).read_bytes()).hexdigest()==sha for n,sha in initial.items())
assert 'queue.PowerManaged=WdfTrue'in s and 'attributes.SynchronizationScope=WdfSynchronizationScopeDevice'in s
v.update(ASan_UBSan=True,source_sha256=initial,native_operations=0,limits=['WDF/VHF/hardware entry and firmware services are modeled.','This checks root control, live input state and cleanup, not native MMIO or Windows pointer delivery.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
