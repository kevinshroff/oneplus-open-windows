#include "gpu_owner.h"
static NTSTATUS RamFrame(OGO_CONTEXT*p,ULONGLONG g){
 if(!p->Ram||p->RamThread!=PsGetCurrentThread()||p->OperationThread!=PsGetCurrentThread()||p->Generation!=g||!p->Ram->Initialized||p->Ram->Tables.ActivationQualified)return STATUS_INVALID_DEVICE_STATE;
 for(ULONG i=0;i<G321_MAX_EXTENTS;i++)if(p->Ram->Buffer[i].Mapped||p->Ram->Buffer[i].MapAttempted)return STATUS_DEVICE_BUSY;
 /* Private never-published backing can be retired after source revocation. */
 return STATUS_SUCCESS;
}
static NTSTATUS RamEnter(PVOID x,ULONGLONG g){OGO_CONTEXT*p=x;LARGE_INTEGER t;t.QuadPart=-500000;NTSTATUS st=KeWaitForSingleObject(&p->RamLock,Executive,KernelMode,FALSE,&t);if(st!=STATUS_SUCCESS)return st;if(p->RamThread){KeReleaseMutex(&p->RamLock,FALSE);return STATUS_DEVICE_BUSY;}p->RamThread=PsGetCurrentThread();st=RamFrame(p,g);if(st!=STATUS_SUCCESS){p->RamThread=NULL;KeReleaseMutex(&p->RamLock,FALSE);}return st;}
static VOID RamLeave(PVOID x){OGO_CONTEXT*p=x;if(p->RamThread==PsGetCurrentThread()){p->RamThread=NULL;KeReleaseMutex(&p->RamLock,FALSE);}}
static NTSTATUS RamLease(PVOID x,ULONGLONG g){return RamFrame(x,g);}
static NTSTATUS RamStopped(PVOID x,ULONGLONG serial,ULONGLONG g){OGO_CONTEXT*p=x;NTSTATUS st=RamFrame(p,g);return st==STATUS_SUCCESS&&serial&&serial==p->Serial?STATUS_SUCCESS:STATUS_INVALID_DEVICE_STATE;}
static BOOLEAN RamEmpty(G321_INACTIVE_RUNTIME*r){if(r->Poisoned||r->Tables.Pool||r->Tables.Ranges||r->Tables.Visited||r->ImageCopy||r->Tables.ActivationQualified||(r->Attempted&&!r->Closed))return FALSE;for(ULONG i=0;i<G321_MAX_EXTENTS;i++)if(r->Buffer[i].Mdl||r->Buffer[i].Cpu||r->Buffer[i].MapAttempted||r->Buffer[i].Mapped)return FALSE;return TRUE;}
static NTSTATUS RetireRam(OGO_CONTEXT*p){if(!p->Ram)return STATUS_SUCCESS;NTSTATUS st=STATUS_SUCCESS;if(p->Ram->Attempted&&!p->Ram->Closed){if(p->Serial==MAXULONGLONG)return STATUS_INTEGER_OVERFLOW;p->Serial++;st=G321ReleaseInactiveStopped(p->Ram,p->Serial);}if(st==STATUS_SUCCESS&&RamEmpty(p->Ram)){ExFreePoolWithTag(p->Ram,OGO_TAG);p->Ram=NULL;OgoFreeInputs(p);}else if(st==STATUS_SUCCESS)st=STATUS_DEVICE_BUSY;return st;}
BOOLEAN OgoSafe(OGO_CONTEXT*p){return !p->GpuUser.Referenced&&!p->Cp&&!p->ThreadLive&&!p->PowerBusy&&!p->Gmu&&!p->Uncertain&&!p->Active&&!p->Fault&&!p->Bank.Native.Referenced&&!p->Bank.Bound&&!p->Bank.QuerySucceeded&&!p->Ram&&!p->Io.MappedMask&&!p->Life.Initialized&&!p->Hold.ScopeHeld&&!p->Hold.Clock.File&&!p->Hold.Clock.Token;}
static NTSTATUS AbortCold(OGO_CONTEXT*p){NTSTATUS st=STATUS_SUCCESS;
 if(p->Active)return STATUS_DEVICE_BUSY;
 if(p->Fault){st=p->Bank.Api.DisconnectFaultUnpublished(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->Fault);if(st!=STATUS_SUCCESS)return st;}
 if(p->GpuUser.Referenced){st=p->Bank.Api.ReleaseGpuUserUnpublished(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser);if(st!=STATUS_SUCCESS)return st;}
 if(p->Bank.Bound){st=OpenLocalBankDisconnectUnpublished(&p->Bank);if(st!=STATUS_SUCCESS)return st;}else if(p->Bank.QuerySucceeded||p->Bank.Native.Referenced)return STATUS_DEVICE_BUSY;
 if(p->Hold.ScopeHeld){st=CghNativeReleaseToReset(&p->Hold);if(st==STATUS_SUCCESS)st=CghNativeLeave(&p->Hold);if(st!=STATUS_SUCCESS)return st;}
 st=RetireRam(p);if(st!=STATUS_SUCCESS)return st;
 if(p->Life.Initialized){st=CghNativeRetire(&p->Hold,&p->Life,&p->Io);if(st!=STATUS_SUCCESS)return st;p->Life.Initialized=FALSE;}else if(p->Io.MappedMask)st=G482Release(&p->Io);
 return st;
}
static NTSTATUS Recheck(OGO_CONTEXT*p){return InterlockedCompareExchange(&p->Revoked,0,0)||!p->Started||!p->D0||p->Removing||p->StopPending||p->RemovePending?STATUS_DEVICE_NOT_READY:STATUS_SUCCESS;}
void G1287SmcSetCp0(OAS_SCM_FRAME*);
C_ASSERT(sizeof(OAS_SCM_FRAME)==88);
C_ASSERT(FIELD_OFFSET(OAS_SCM_FRAME,Entries)==64);
static NTSTATUS ApertureColdSetup(PVOID x,OAS_BOOTSTRAP*a){
 OGO_CONTEXT*p=x;if(!p||!a)return STATUS_INVALID_DEVICE_STATE;OAS_COLD_SETUP*s=&a->Setup;OGU_TOKEN*t=&p->GpuUser;
 if(!p||p->Active!=a||!p->CpInit||!OgoApertureRequested()||p->Gmu||p->Cp||a->State!=OAS_OPEN||a->ColdConsumed||p->Hold.BootCommitted||s->Attempted||s->Completed||Recheck(p)!=STATUS_SUCCESS||p->OperationThread!=PsGetCurrentThread()||a->OperationThread!=p->OperationThread||!a->Scope.Token)return STATUS_INVALID_DEVICE_STATE;
 if(!t->Referenced||!t->Qualified||t->Sid||t->Bank||t->Asid||t->Slot!=1||t->Id!=s->GpuId||t->Generation!=s->GpuGeneration||t->Serial!=s->GpuSerial||p->Generation!=s->OwnerGeneration||p->RunId!=s->RunId||p->Hold.Generation!=s->Generation||p->Hold.Serial!=s->Serial||p->Hold.Hold.state!=CGH_RESET_QUIESCENT||!p->Hold.Hold.reset_mode)return STATUS_INVALID_DEVICE_STATE;
 if(!OgoConsumeAperture())return STATUS_INVALID_DEVICE_STATE;
 /* Consume generation-bound once authority BEFORE potentially unfinished monitor entry. */
 s->Attempted=TRUE;s->Status=STATUS_DEVICE_NOT_READY;
 DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1287 aperture begin run%llx gen%llx serial%llx gpu%llx; NORMAL64 only\n",p->RunId,s->Generation,s->Serial,s->GpuId);
 G1287SmcSetCp0(&s->Frame);s->Transport=OasScmTransport(&s->Frame);
 DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1287 aperture returned run%llx x0%llx x1%llx entries%llu returns%llu interrupts%llu transport%u\n",p->RunId,s->Frame.X[0],s->Frame.X[1],s->Frame.Entries,s->Frame.Returns,s->Frame.Interrupted,s->Transport);
 /* Retained normal dispatcher SXTW(handlerW0)->task+30->frame[0].
  * Handler zero completes; support failure16 remains raw x0=16, NOT INFO's x1 boolean.
  * Other states retain; no busy/WAITQ replay or guessed service completion. */
 s->DispatchKnown=(BOOLEAN)(OasScmFrameValid(&s->Frame)&&(s->Frame.X[0]==0||s->Frame.X[0]==16));s->DispatchStatus=s->Frame.X[0];
 if(s->Transport==OAS_SCM_TRANSPORT_COMPLETE&&s->DispatchKnown&&s->DispatchStatus==0){
  s->Completed=TRUE; /* setter completion is distinct from owner/post-hardware currentness */
  if(Recheck(p)!=STATUS_SUCCESS||p->Active!=a||p->Generation!=s->OwnerGeneration||p->RunId!=s->RunId||p->OperationThread!=PsGetCurrentThread()||a->OperationThread!=p->OperationThread||!a->Scope.Token||p->Hold.Generation!=s->Generation||p->Hold.Serial!=s->Serial||!t->Referenced||!t->Qualified||t->Id!=s->GpuId||t->Generation!=s->GpuGeneration||t->Serial!=s->GpuSerial||t->Sid||t->Bank||t->Asid||t->Slot!=1)return s->Status=STATUS_DEVICE_NOT_READY;
  return s->Status=STATUS_SUCCESS;
 }
 return s->Status=s->Transport==OAS_SCM_ERROR?STATUS_UNSUCCESSFUL:STATUS_NOT_SUPPORTED;
}
NTSTATUS OgoBootstrap(OGO_CONTEXT*p){NTSTATUS st=Recheck(p);p->OperationThread=PsGetCurrentThread();p->GmuStatus=STATUS_NOT_SUPPORTED;
 if(st!=STATUS_SUCCESS)goto fail;
 p->Ram=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*p->Ram),OGO_TAG);if(!p->Ram){st=STATUS_INSUFFICIENT_RESOURCES;goto fail;}G321InactiveInitialize(p->Ram);p->Serial=1;
 st=OgoLoadInputs(p);if(st!=STATUS_SUCCESS)goto fail;G321_OWNER owner={p,RamEnter,RamLeave,RamLease,RamStopped,NULL};
 st=G321PrepareInactive(p->Ram,&owner,&p->Inputs,p->Generation,p->Serial);if(st!=STATUS_SUCCESS)goto fail;p->Phase=OGO_RAM;
 st=Recheck(p);if(st!=STATUS_SUCCESS)goto fail;
 G482Initialize(&p->Io);st=G482Bind(&p->Io,p->Pdo,p->Resources);if(st!=STATUS_SUCCESS)goto fail;
 st=G515Initialize(&p->Life,p->Pdo);if(st!=STATUS_SUCCESS)goto fail;
 st=CghNativeObserveStarted(&p->Life,&p->Io);if(st!=STATUS_SUCCESS)goto fail;p->Phase=OGO_D0;
 st=Recheck(p);if(st!=STATUS_SUCCESS)goto fail;
 st=CghNativeAcquire(&p->Hold,&p->Life,&p->Io);if(st!=STATUS_SUCCESS)goto fail;p->Phase=OGO_HOLD;
 st=OpenLocalBankConnect(&p->Bank,&p->Hold);if(st!=STATUS_SUCCESS)goto fail;OLB_CLAIM claim;st=p->Bank.Api.Qualify(p->Bank.Api.Interface.Context,&p->Bank.Native,&claim);if(st!=STATUS_SUCCESS)goto fail;p->Phase=OGO_BANK;
 if(p->CpInit){st=p->Bank.Api.ReserveGpuUser(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser);if(st!=STATUS_SUCCESS)goto fail;}
 st=p->Bank.Api.ConnectFault(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->Fault);if(st!=STATUS_SUCCESS)goto fail;p->Phase=OGO_IRQ;
 st=Recheck(p);if(st!=STATUS_SUCCESS)goto fail;
 OAS_COLD_SETUP setup;RtlZeroMemory(&setup,sizeof(setup));
 if(OgoApertureRequested()){
  if(!p->CpInit||!p->GpuUser.Referenced||!p->GpuUser.Qualified){st=STATUS_INVALID_DEVICE_STATE;goto fail;}
  st=p->Bank.Api.CheckGpuUser(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser,NULL);if(st!=STATUS_SUCCESS)goto fail;
  setup.Context=p;setup.Run=ApertureColdSetup;setup.OwnerGeneration=p->Generation;setup.RunId=p->RunId;setup.Generation=p->Hold.Generation;setup.Serial=p->Hold.Serial;setup.GpuId=p->GpuUser.Id;setup.GpuGeneration=p->GpuUser.Generation;setup.GpuSerial=p->GpuUser.Serial;
 }
 st=OasColdActivateFromInactiveSetup(p->Ram,&p->Hold,&p->Bank,&p->Fault,&p->Active,setup.Run?&setup:NULL);if(st!=STATUS_SUCCESS)goto fail;
 p->Phase=OGO_TRANSLATION;
 st=OgoRunGmu(p);p->GmuStatus=st;if(st!=STATUS_SUCCESS)goto fail;
 p->Phase=10;if(p->CpInit){st=OgoRunCpFence1(p);if(st!=STATUS_SUCCESS)goto fail;p->Phase=11;}(void)RetireRam(p);p->Status=STATUS_SUCCESS;return STATUS_SUCCESS;
fail:p->Status=st;p->CleanupStatus=AbortCold(p);if(p->CleanupStatus!=STATUS_SUCCESS){p->Uncertain=TRUE;p->Phase=OGO_RETAINED;(void)CghNativeRetainFailure(&p->Hold,st==STATUS_SUCCESS?p->CleanupStatus:st);}return st;
}
