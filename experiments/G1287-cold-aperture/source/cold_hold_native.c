/* SPDX-License-Identifier: MIT -- real assigned-resource bridge, no IOCTL. */
#include "cold_hold_native.h"
#include "native_bootstrap.h"
#include "broker/open_parent_consumer.h"
#include <intrin.h>
#include <devpkey.h>
static volatile LONG64 CghSerial;
static int Frame(CGH_NATIVE*n){G515_LIFE*l=n->Life;return n->ScopeHeld&&!n->Poisoned&&n->Thread==PsGetCurrentThread()&&l&&l->HeldThread==n->Thread&&l->Generation==n->Generation&&l->StartObserved&&l->OsD0Candidate&&!l->Removed&&!InterlockedCompareExchange(&l->Inhibit,0,0)&&n->Io&&n->Io->Bound&&n->Io->MappedMask==31&&n->Io->Pdo==l->Pdo&&l->Io==n->Io&&KeGetCurrentIrql()==PASSIVE_LEVEL?0:-1;}
static NTSTATUS ClientCurrent(PVOID x,PDEVICE_OBJECT p,ULONGLONG g){CGH_NATIVE*n=x;return !Frame(n)&&n->Life->Pdo==p&&n->Generation==g?STATUS_SUCCESS:STATUS_INVALID_DEVICE_STATE;}
static NTSTATUS ClientDrained(PVOID x,PDEVICE_OBJECT p,ULONGLONG g){CGH_NATIVE*n=x;if(ClientCurrent(x,p,g)!=STATUS_SUCCESS)return STATUS_INVALID_DEVICE_STATE;return !n->BootCommitted&&(n->Hold.state==CGH_RELEASED||n->Hold.state==CGH_RESET_RELEASED)&&n->ReleasedSerial==n->Serial&&n->Hold.serial==n->Serial&&n->Hold.reset==1&&!(n->Hold.hfi&1)&&(n->Hold.gx&1)?STATUS_SUCCESS:STATUS_DEVICE_BUSY;}
static int Current(void*x,uint64_t g){CGH_NATIVE*n=x;return !Frame(n)&&n->Clock.Bound&&n->Clock.Token&&n->Generation==g?0:-1;}
static int Read(void*x,unsigned b,uint32_t o,uint32_t*v){CGH_NATIVE*n=x;if(Current(n,n->Generation))return -1;NTSTATUS s=STATUS_ACCESS_DENIED;ULONG value=0;
 if(b==CGH_GPU&&(o==0xf114||o==0xf118))s=G482GpuRead(n->Io,o,&value);
 else if(b==CGH_CORE&&(o==0x14000||o==0x14600||o==0x14340||o==0x24c40))s=G482CoreRead(n->Io,o,&value);
 else if(b==CGH_RSC&&(o==0xd28||o==0xfc8||o==0x1268||o==0x1508))s=G482RscRead(n->Io,o,&value);
 if(s==STATUS_SUCCESS)*v=(uint32_t)value;return s==STATUS_SUCCESS&&value!=MAXULONG?0:-1;
}
static int WriteHalt(void*x,uint32_t before,uint32_t desired){CGH_NATIVE*n=x;uint32_t current;
 if(Current(n,n->Generation)||Read(n,CGH_GPU,0xf114,&current)||current!=before)return -1;
 if(n->Hold.reset_mode){
  /* Only actual cold-reset begin + consumed boot handoff can reach this.
   * No public raw write API, caller success flag, ACK write or retry. */
  if(n->Hold.state!=CGH_BOOT_UNHALTING||n->Hold.attempted!=1||n->Hold.writes!=1||n->Hold.owned||n->Hold.before_halt!=8||before!=8||desired!=0)return -1;
 }else if(((before^desired)&~2u)||!((before^desired)&2u))return -1;
 return G482GpuWrite(n->Io,0xf114,desired)==STATUS_SUCCESS?0:-1;
}
static VOID Barrier(void*x){UNREFERENCED_PARAMETER(x);__dsb(_ARM64_BARRIER_OSH);}
static VOID Delay(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(10);}
static NTSTATUS Witness(CGH_NATIVE*n){OPEN_GMU_CLOCK_SNAPSHOT s;NTSTATUS st=n->Clock.Api.Witness(n->Clock.Api.Interface.Context,n->Clock.Token,&s);if(st!=STATUS_SUCCESS)return st;if(s.Size!=sizeof(s)||s.Version!=1||!s.Generation||(n->ClockGeneration&&n->ClockGeneration!=s.Generation))return STATUS_DEVICE_CONFIGURATION_ERROR;n->ClockGeneration=s.Generation;return STATUS_SUCCESS;}
static NTSTATUS Failed(CGH_NATIVE*n,NTSTATUS st){
 n->Status=st;n->Poisoned=(n->Clock.File||n->Clock.Token||n->Hold.attempted)?TRUE:FALSE;
 if(n->Hold.attempted)n->Hold.state=CGH_POISONED;
 /* Retain clock/file/context/code/mappings after uncertainty. Never return a
  * worker thread to the OS while it still owns our software mutex. The real
  * caller must use CanDispose and retain embedded context/code until reset. */
 if(n->ScopeHeld&&n->Thread==PsGetCurrentThread()){InterlockedExchange(&n->Life->Inhibit,1);n->Life->HeldThread=NULL;n->ScopeHeld=FALSE;n->Thread=NULL;KeReleaseMutex(&n->Life->Lock,FALSE);}return st;
}
/* Owner-thread invalidation must retain hardware ownership and relinquish
 * the software mutex. A foreign thread must never unlock another owner. */
static NTSTATUS InvalidOwned(CGH_NATIVE*n,NTSTATUS st){
 if(n&&n->ScopeHeld&&n->Thread==PsGetCurrentThread()&&n->Life&&n->Life->HeldThread==n->Thread)return Failed(n,st);
 return st;
}
static NTSTATUS Result(CGH_NATIVE*n,enum cgh_status e){if(e==CGH_OK)return n->Status=STATUS_SUCCESS;return Failed(n,e==CGH_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_HARDWARE_ERROR);}
NTSTATUS CghNativeAcquire(CGH_NATIVE*n,G515_LIFE*l,G482_BINDING*b){
 if(!n||!l||!b||n->ScopeHeld||n->Clock.File||n->Hold.state!=CGH_NEW||KeGetCurrentIrql()!=PASSIVE_LEVEL||!PsIsSystemThread(PsGetCurrentThread()))return STATUS_INVALID_DEVICE_STATE;
 if(!l->Initialized||l->Pdo!=b->Pdo||!OpenExactHardwareId(l->Pdo,L"ACPI\\OPEN0515"))return STATUS_ACCESS_DENIED;
 LARGE_INTEGER timeout;timeout.QuadPart=-500000;NTSTATUS st=KeWaitForSingleObject(&l->Lock,Executive,KernelMode,FALSE,&timeout);if(st!=STATUS_SUCCESS)return st;
 if(l->HeldThread||!l->Generation||l->Removed||!l->StartObserved||!l->OsD0Candidate||InterlockedCompareExchange(&l->Inhibit,0,0)||l->Io!=b||!b->Bound||b->MappedMask!=31){KeReleaseMutex(&l->Lock,FALSE);return STATUS_DEVICE_NOT_READY;}
 LONG64 issued=InterlockedIncrement64(&CghSerial);if(issued<=0){KeReleaseMutex(&l->Lock,FALSE);return STATUS_INTEGER_OVERFLOW;}ULONGLONG serial=(ULONGLONG)issued;
 n->Life=l;n->Io=b;n->Thread=PsGetCurrentThread();n->Generation=l->Generation;n->Serial=serial;n->ScopeHeld=TRUE;l->HeldThread=n->Thread;
 OPEN_CLOCK_CLIENT c;RtlZeroMemory(&c,sizeof(c));c.Size=sizeof(c);c.Version=OPEN_CLOCK_VERSION;c.Role=OPEN_CLOCK_GPU_CLIENT;c.Pdo=l->Pdo;c.Context=n;c.Generation=n->Generation;c.Current=ClientCurrent;c.Drained=ClientDrained;
 st=OpenGmuClockConnect(&n->Clock,&c);if(st!=STATUS_SUCCESS)return Failed(n,st);
 st=Witness(n);if(st!=STATUS_SUCCESS)return Failed(n,st);
 CGH_IO io={n,n->Generation,Current,Read,WriteHalt,Barrier,Delay};return Result(n,CghResetAcquire(&n->Hold,&io,serial));
}
NTSTATUS CghNativeCheck(CGH_NATIVE*n){if(n&&n->BootCommitted)return STATUS_NOT_SUPPORTED;if(!n||Frame(n)||!n->Clock.Token)return InvalidOwned(n,STATUS_INVALID_DEVICE_STATE);NTSTATUS st=Witness(n);if(st!=STATUS_SUCCESS)return Failed(n,st);return Result(n,n->Hold.reset_mode?CghResetCheck(&n->Hold):CghCheck(&n->Hold));}
NTSTATUS CghNativeReleaseToReset(CGH_NATIVE*n){NTSTATUS st=CghNativeCheck(n);if(st!=STATUS_SUCCESS)return st;st=Result(n,n->Hold.reset_mode?CghResetReleaseUnpublished(&n->Hold):CghReleaseToReset(&n->Hold,10000));if(st==STATUS_SUCCESS)n->ReleasedSerial=n->Serial;return st;}
NTSTATUS CghNativeLeave(CGH_NATIVE*n){if(!n||Frame(n))return InvalidOwned(n,STATUS_INVALID_DEVICE_STATE);if(n->BootCommitted||(n->Hold.state!=CGH_RELEASED&&n->Hold.state!=CGH_RESET_RELEASED)||n->ReleasedSerial!=n->Serial)return STATUS_DEVICE_BUSY;
 NTSTATUS st=Witness(n);if(st!=STATUS_SUCCESS)return Failed(n,st);st=Result(n,n->Hold.reset_mode?CghResetCheckReleased(&n->Hold):CghCheckReleased(&n->Hold));if(st!=STATUS_SUCCESS)return st;
 st=OpenGmuClockDisconnect(&n->Clock);if(st!=STATUS_SUCCESS)return Failed(n,st);
 n->Life->HeldThread=NULL;n->ScopeHeld=FALSE;n->Thread=NULL;KeReleaseMutex(&n->Life->Lock,FALSE);return n->Status=STATUS_SUCCESS;
}

NTSTATUS CghNativeCommitToBoot(CGH_NATIVE*n){if(!n||Frame(n))return InvalidOwned(n,STATUS_INVALID_DEVICE_STATE);if(n->BootCommitted||(n->Hold.reset_mode?n->Hold.state!=CGH_BOOT_RELEASED:n->Hold.state!=CGH_RELEASED)||n->ReleasedSerial!=n->Serial)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=Witness(n);if(st!=STATUS_SUCCESS)return Failed(n,st);st=Result(n,n->Hold.reset_mode?CghResetCheckBootReleased(&n->Hold):CghCheckReleased(&n->Hold));if(st!=STATUS_SUCCESS)return st;n->BootCommitted=TRUE;n->ReleasedSerial=0;return n->Status=STATUS_SUCCESS;}
NTSTATUS CghNativeCanDispose(CGH_NATIVE*n){if(!n||n->ScopeHeld||n->Poisoned||n->Clock.File||n->Clock.Token||n->Clock.Bound||n->Hold.owned||n->Hold.state==CGH_HELD||n->Hold.state==CGH_MUTATING||n->Hold.state==CGH_POISONED||n->Hold.state==CGH_RESET_QUIESCENT||n->Hold.state==CGH_BOOT_UNHALTING||n->Hold.state==CGH_BOOT_RELEASED||n->BootCommitted)return STATUS_DEVICE_BUSY;return STATUS_SUCCESS;}

NTSTATUS CghNativeObserveStarted(G515_LIFE*l,G482_BINDING*b){
 if(!l||!b||!l->Initialized||!b->Bound||b->MappedMask!=31||l->Pdo!=b->Pdo||KeGetCurrentIrql()!=PASSIVE_LEVEL||!PsIsSystemThread(PsGetCurrentThread())||!OpenExactHardwareId(l->Pdo,L"ACPI\\OPEN0515"))return STATUS_INVALID_DEVICE_STATE;
 LARGE_INTEGER wait;wait.QuadPart=-500000;NTSTATUS st=KeWaitForSingleObject(&l->Lock,Executive,KernelMode,FALSE,&wait);if(st!=STATUS_SUCCESS)return st;
 if(l->HeldThread||l->Removed||l->Generation||l->StartObserved){KeReleaseMutex(&l->Lock,FALSE);return STATUS_DEVICE_BUSY;}
 CM_POWER_DATA power;DEVPROPTYPE type=0;ULONG bytes=0;RtlZeroMemory(&power,sizeof(power));st=IoGetDevicePropertyData(l->Pdo,&DEVPKEY_Device_PowerData,LOCALE_NEUTRAL,0,sizeof(power),&power,&bytes,&type);
 if(st==STATUS_SUCCESS&&(type!=DEVPROP_TYPE_BINARY||bytes!=sizeof(power)||power.PD_Size!=sizeof(power)||power.PD_MostRecentPowerState!=PowerDeviceD0))st=STATUS_DEVICE_NOT_READY;
 if(st==STATUS_SUCCESS){l->Generation++;l->Io=b;l->StartObserved=TRUE;l->OsD0Candidate=TRUE;l->PowerSource=1;l->Requested=PowerDeviceD0;InterlockedExchange(&l->Inhibit,0);}else{l->StartObserved=FALSE;l->OsD0Candidate=FALSE;InterlockedExchange(&l->Inhibit,1);}l->PropertyStatus=st;l->Status=st;KeReleaseMutex(&l->Lock,FALSE);return st;
}

NTSTATUS CghNativeRetire(CGH_NATIVE*n,G515_LIFE*l,G482_BINDING*b){
 if(!n||!l||!b||KeGetCurrentIrql()!=PASSIVE_LEVEL||!l->Initialized||
    (n->Life&&n->Life!=l)||(n->Io&&n->Io!=b)||(b->Pdo&&b->Pdo!=l->Pdo))return STATUS_INVALID_PARAMETER;
 NTSTATUS st=CghNativeCanDispose(n);if(st!=STATUS_SUCCESS)return st;
 st=G515Revoke(l,TRUE);if(st!=STATUS_SUCCESS)return st;
 st=CghNativeCanDispose(n);if(st!=STATUS_SUCCESS)return st;
 /* Removed is permanent before these no-MMIO operations. No cold retry. */
 st=G482Release(b);if(st!=STATUS_SUCCESS)return st;
 return G515Dispose(l);
}

NTSTATUS CghNativeRetainFailure(CGH_NATIVE*n,NTSTATUS st){if(st==STATUS_SUCCESS)return STATUS_INVALID_PARAMETER;if(!n||!n->ScopeHeld||n->Thread!=PsGetCurrentThread()||!n->Life||n->Life->HeldThread!=n->Thread||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;return Failed(n,st);}

NTSTATUS CghNativeRuntimeCheck(CGH_NATIVE*n){
 if(!n||Frame(n)||!n->BootCommitted||n->ReleasedSerial||(n->Hold.reset_mode?n->Hold.state!=CGH_BOOT_RELEASED:n->Hold.state!=CGH_RELEASED)||n->Hold.owned||(!n->Hold.reset_mode&&n->Hold.before_halt))return InvalidOwned(n,STATUS_INVALID_DEVICE_STATE);
 NTSTATUS st=Witness(n);if(st!=STATUS_SUCCESS)return Failed(n,st);
 ULONG halt=MAXULONG;st=G482GpuRead(n->Io,0xf114,&halt);if(st!=STATUS_SUCCESS||halt)return Failed(n,st==STATUS_SUCCESS?STATUS_DEVICE_HARDWARE_ERROR:st);
 /* No reset/HFI/GX/TCS-idle assertion: firmware may genuinely be running. */
 return n->Status=STATUS_SUCCESS;
}

NTSTATUS CghNativeUnhaltResetForBoot(CGH_NATIVE*n,PVOID actual_bootstrap){
 OAS_BOOTSTRAP*a=actual_bootstrap;
 if(!a||a->Hold!=n||!a->ColdConsumed||a->State!=OAS_ACTIVE||a->OperationThread!=PsGetCurrentThread()||!a->Scope.Token||!a->Bank||!a->Bank->Bound||a->Bank->Native.Hold!=n||!a->Bank->Native.ProgramPinned||!a->Native.Base||a->Native.Tables!=a->Tables||!a->Tables||a->Tables->Poisoned||a->Tables->Disabled||a->Tables->References<2||a->Tables->Session.Phase!=OSMA_ACTIVE||a->Tables->Session.IoIdentity!=&a->Native||a->Native.Proof.Context!=a||a->Native.Proof.D0!=n||a->Native.Proof.Bank!=&a->Bank->Native||a->Native.Proof.Tables!=a->Tables)return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS ns=a->Bank->Api.CheckNs(a->Bank->Api.Interface.Context,&a->Bank->Native,a->Fault,a,&a->Scope);if(ns!=STATUS_SUCCESS)return ns;
 NTSTATUS st=CghNativeCheck(n);if(st!=STATUS_SUCCESS)return st;
 if(!n->Hold.reset_mode||n->BootCommitted)return STATUS_INVALID_DEVICE_STATE;
 st=Result(n,CghResetUnhaltForBoot(&n->Hold));if(st==STATUS_SUCCESS)n->ReleasedSerial=n->Serial;
 return st;
}
