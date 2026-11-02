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
BOOLEAN OgoSafe(OGO_CONTEXT*p){return !p->ThreadLive&&!p->PowerBusy&&!p->Gmu&&!p->Uncertain&&!p->Active&&!p->Fault&&!p->Bank.Native.Referenced&&!p->Bank.Bound&&!p->Bank.QuerySucceeded&&!p->Ram&&!p->Io.MappedMask&&!p->Life.Initialized&&!p->Hold.ScopeHeld&&!p->Hold.Clock.File&&!p->Hold.Clock.Token;}
static NTSTATUS AbortCold(OGO_CONTEXT*p){NTSTATUS st=STATUS_SUCCESS;
 if(p->Active)return STATUS_DEVICE_BUSY;
 if(p->Fault){st=p->Bank.Api.DisconnectFaultUnpublished(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->Fault);if(st!=STATUS_SUCCESS)return st;}
 if(p->Bank.Bound){st=OpenLocalBankDisconnectUnpublished(&p->Bank);if(st!=STATUS_SUCCESS)return st;}else if(p->Bank.QuerySucceeded||p->Bank.Native.Referenced)return STATUS_DEVICE_BUSY;
 if(p->Hold.ScopeHeld){st=CghNativeReleaseToReset(&p->Hold);if(st==STATUS_SUCCESS)st=CghNativeLeave(&p->Hold);if(st!=STATUS_SUCCESS)return st;}
 st=RetireRam(p);if(st!=STATUS_SUCCESS)return st;
 if(p->Life.Initialized){st=CghNativeRetire(&p->Hold,&p->Life,&p->Io);if(st!=STATUS_SUCCESS)return st;p->Life.Initialized=FALSE;}else if(p->Io.MappedMask)st=G482Release(&p->Io);
 return st;
}
static NTSTATUS Recheck(OGO_CONTEXT*p){return InterlockedCompareExchange(&p->Revoked,0,0)||!p->Started||!p->D0||p->Removing||p->StopPending||p->RemovePending?STATUS_DEVICE_NOT_READY:STATUS_SUCCESS;}
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
 st=p->Bank.Api.ConnectFault(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->Fault);if(st!=STATUS_SUCCESS)goto fail;p->Phase=OGO_IRQ;
 st=Recheck(p);if(st!=STATUS_SUCCESS)goto fail;
 st=OasColdActivateFromInactive(p->Ram,&p->Hold,&p->Bank,&p->Fault,&p->Active);if(st!=STATUS_SUCCESS)goto fail;
 p->Phase=OGO_TRANSLATION;
 st=OgoRunGmu(p);p->GmuStatus=st;if(st!=STATUS_SUCCESS)goto fail;
 p->Phase=10;(void)RetireRam(p);p->Status=STATUS_SUCCESS;return STATUS_SUCCESS;
fail:p->Status=st;p->CleanupStatus=AbortCold(p);if(p->CleanupStatus!=STATUS_SUCCESS){p->Uncertain=TRUE;p->Phase=OGO_RETAINED;(void)CghNativeRetainFailure(&p->Hold,st==STATUS_SUCCESS?p->CleanupStatus:st);}return st;
}
