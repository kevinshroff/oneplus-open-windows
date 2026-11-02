#include "native_bootstrap.h"
#define TAG 'BsAO'
#define NEED (OSMA_CURRENT|OSMA_PHYSICAL_STOP|OSMA_BANK_STREAM|OSMA_SECURE_ACCESS|OSMA_TABLES_VISIBLE|OSMA_FAULT_HANDLER|OSMA_NS_BLOCK)
static OSMA_REQUEST Q(OAS_BOOTSTRAP*a){OSMA_REQUEST q;RtlZeroMemory(&q,sizeof(q));q.Bank=q.Asid=a->BankIndex;q.Slot=a->Slot;q.Proof=a->Native.Proof;return q;}
static int Aggregate(void*x,const OSMA_PROOFS*p,unsigned needs,unsigned sid,unsigned bank,unsigned asid,unsigned slot){OAS_BOOTSTRAP*a=x;
 if(!a||a->ColdConsumed||!p||needs&~NEED||sid!=5||bank!=a->BankIndex||asid!=bank||slot!=a->Slot||a->OperationThread!=PsGetCurrentThread()||!a->Tables||!a->Hold||!a->Bank||!a->Bank->Bound||!a->Scope.Token||a->State==OAS_RETAINED||a->State==OAS_CLOSED||p->Context!=a||p->D0!=a->Hold||p->Bank!=&a->Bank->Native||p->Security!=&a->Scope||p->Tables!=a->Tables||p->Fault!=a->Fault||p->NsBlock!=&a->Scope||p->Generation!=a->Hold->Generation||p->StopSerial!=a->Hold->Serial||a->Tables->Generation!=a->AllocationGeneration)return -1;
 if(CghNativeCheck(a->Hold)!=STATUS_SUCCESS)return -2;
 if(a->Bank->Api.CheckNs(a->Bank->Api.Interface.Context,&a->Bank->Native,a->Fault,a,&a->Scope)!=STATUS_SUCCESS)return -3;
 OSMA_REQUEST q=Q(a);q.Proof=*p;
 if(a->Bank->Api.CheckBank(a->Bank->Api.Interface.Context,&a->Bank->Native,&q)!=STATUS_SUCCESS||a->Bank->Api.CheckFault(a->Bank->Api.Interface.Context,&a->Bank->Native,a->Fault,&q)!=STATUS_SUCCESS)return -4;
 if(needs&OSMA_TABLES_VISIBLE){if(a->Native.Base&&a->Tables->References<2)return -5;if(OasMakeNcVisible(a->Tables)!=STATUS_SUCCESS){a->Tables->Poisoned=TRUE;return -6;}}
 return 0;
}
static NTSTATUS Begin(OAS_BOOTSTRAP*a){if(!a||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;LARGE_INTEGER timeout;timeout.QuadPart=-500000;NTSTATUS st=KeWaitForSingleObject(&a->Operation,Executive,KernelMode,FALSE,&timeout);if(st!=STATUS_SUCCESS)return st;
 if(a->OperationThread||a->State==OAS_RETAINED||a->State==OAS_CLOSED){KeReleaseMutex(&a->Operation,FALSE);return STATUS_DEVICE_BUSY;}a->OperationThread=PsGetCurrentThread();
 st=a->Bank->Api.EnterNs(a->Bank->Api.Interface.Context,&a->Bank->Native,a->Fault,a,&a->Scope);
 if(st==STATUS_SUCCESS&&a->ProviderGeneration&&a->ProviderGeneration!=a->Scope.ProviderGeneration){(void)a->Bank->Api.LeaveNs(a->Bank->Api.Interface.Context,a,&a->Scope);st=STATUS_INVALID_DEVICE_STATE;}
 if(st!=STATUS_SUCCESS){a->OperationThread=NULL;KeReleaseMutex(&a->Operation,FALSE);}return st;
}
static NTSTATUS End(OAS_BOOTSTRAP*a,NTSTATUS st){NTSTATUS leave=a->Bank->Api.LeaveNs(a->Bank->Api.Interface.Context,a,&a->Scope);a->OperationThread=NULL;KeReleaseMutex(&a->Operation,FALSE);if(leave!=STATUS_SUCCESS){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,leave);return leave;}return st;}
NTSTATUS OasTakeAndOpen(G321_INACTIVE_RUNTIME*r,CGH_NATIVE*h,OPEN_LOCAL_BANK_CLIENT*b,PVOID*fault,OAS_BOOTSTRAP**out){
 if(!out||!r||!h||!b||!b->Bound||!b->Native.Referenced||!fault||!*fault||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;*out=NULL;
 NTSTATUS st=CghNativeCheck(h);if(st!=STATUS_SUCCESS)return st;if(b->Hold!=h||b->Native.Hold!=h)return STATUS_ACCESS_DENIED;
 OAS_BOOTSTRAP*a=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*a),TAG);if(!a)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(a,sizeof(*a));KeInitializeMutex(&a->Operation,0);a->Hold=h;a->Bank=b;a->Fault=*fault;*fault=NULL;*out=a;
 st=OsmaTakeInactiveTables(r,h->Life->Pdo,&a->Tables);if(st!=STATUS_SUCCESS)return a->Status=st;a->AllocationGeneration=a->Tables->Generation;
 OSMA_REQUEST q;RtlZeroMemory(&q,sizeof(q));st=b->Api.BindRequest(b->Api.Interface.Context,&b->Native,&q);if(st!=STATUS_SUCCESS)return a->Status=st;a->BankIndex=q.Bank;a->Slot=q.Slot;
 a->Native.Proof=(OSMA_PROOFS){a,h,&b->Native,&a->Scope,a->Tables,a->Fault,NULL,&a->Scope,h->Generation,h->Serial,Aggregate};
 st=Begin(a);if(st!=STATUS_SUCCESS)return a->Status=st;a->ProviderGeneration=a->Scope.ProviderGeneration;
 st=OasMakeNcVisible(a->Tables);if(st!=STATUS_SUCCESS){a->Tables->Poisoned=TRUE;a->State=OAS_RETAINED;}
 if(st==STATUS_SUCCESS){OSMA_PROOFS proof=a->Native.Proof;st=OsmaOpenNativeIo(&a->Native,b->Api.ProviderPdo,&a->Scope.Grant,a->Tables,&proof,a->BankIndex,a->Slot);}
 st=End(a,st);if(st==STATUS_SUCCESS)a->State=OAS_OPEN;return a->Status=st;
}
NTSTATUS OasActivate(OAS_BOOTSTRAP*a){if(!a||a->State!=OAS_OPEN||!a->Native.Base)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=Begin(a);if(st!=STATUS_SUCCESS){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);return a->Status=st;}
 OSMA_REQUEST q=Q(a);if(Aggregate(a,&a->Native.Proof,NEED,5,q.Bank,q.Asid,q.Slot))st=STATUS_DEVICE_NOT_READY;
 /* Setup runs inside this actual cold namespace before any table programming. */
 if(st==STATUS_SUCCESS&&a->Setup.Run){st=a->Setup.Run(a->Setup.Context,a);a->Setup.Status=st;
  if(st==STATUS_SUCCESS&&(!a->Setup.Attempted||!a->Setup.Completed))st=STATUS_INVALID_DEVICE_STATE;
  if(st==STATUS_SUCCESS&&Aggregate(a,&a->Native.Proof,NEED,5,q.Bank,q.Asid,q.Slot))st=STATUS_DEVICE_NOT_READY;
  if(OasSetupRetains(a->Setup.Attempted,st==STATUS_SUCCESS))a->State=OAS_RETAINED;
 }
 if(st==STATUS_SUCCESS){st=a->Bank->Api.PinProgramming(a->Bank->Api.Interface.Context,&a->Bank->Native,&q);if(st==STATUS_SUCCESS){a->State=OAS_ATTEMPTING;st=OsmaActivateOwnedBinding(&a->Native);if(st==STATUS_SUCCESS)a->State=OAS_ACTIVE;else a->State=OAS_RETAINED;}}
 if(OasSetupRetains(a->Setup.Attempted,st==STATUS_SUCCESS))a->State=OAS_RETAINED;
 st=End(a,st);if(st!=STATUS_SUCCESS&&(a->Bank->Native.ProgramPinned||a->Setup.Attempted)){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);}return a->Status=st;
}
NTSTATUS OasAbortUnpublished(OAS_BOOTSTRAP*a){
 if(!a||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 LARGE_INTEGER wait;wait.QuadPart=-500000;NTSTATUS st=KeWaitForSingleObject(&a->Operation,Executive,KernelMode,FALSE,&wait);if(st!=STATUS_SUCCESS)return st;
 if(a->OperationThread||a->State==OAS_ACTIVE||a->State==OAS_ATTEMPTING||a->State==OAS_RETAINED||a->Bank->Native.ProgramPinned){KeReleaseMutex(&a->Operation,FALSE);return STATUS_DEVICE_BUSY;}
 if(a->Native.Base){st=OsmaCloseNativeIo(&a->Native);if(st!=STATUS_SUCCESS)goto retain;}
 if(a->Tables){st=OsmaFreeRetiredBinding(a->Tables);if(st!=STATUS_SUCCESS)goto retain;a->Tables=NULL;}
 if(a->Fault){st=a->Bank->Api.DisconnectFaultUnpublished(a->Bank->Api.Interface.Context,&a->Bank->Native,&a->Fault);if(st!=STATUS_SUCCESS)goto retain;}
 st=OpenLocalBankDisconnectUnpublished(a->Bank);if(st!=STATUS_SUCCESS)goto retain;
 st=CghNativeReleaseToReset(a->Hold);if(st==STATUS_SUCCESS)st=CghNativeLeave(a->Hold);if(st!=STATUS_SUCCESS)goto retain;
 a->State=OAS_CLOSED;KeReleaseMutex(&a->Operation,FALSE);ExFreePoolWithTag(a,TAG);return STATUS_SUCCESS;
retain:a->State=OAS_RETAINED;KeReleaseMutex(&a->Operation,FALSE);(void)CghNativeRetainFailure(a->Hold,st);return a->Status=st;
}

NTSTATUS OasColdActivateFromInactiveSetup(G321_INACTIVE_RUNTIME*r,CGH_NATIVE*h,OPEN_LOCAL_BANK_CLIENT*b,PVOID*fault,OAS_BOOTSTRAP**out,const OAS_COLD_SETUP*setup){
 if(!out||!h||!b||b->Hold!=h||b->Native.Hold!=h||!fault||!*fault)return STATUS_INVALID_PARAMETER;*out=NULL;
 NTSTATUS st=OasTakeAndOpen(r,h,b,fault,out);if(st==STATUS_SUCCESS){if(setup)(*out)->Setup=*setup;st=OasActivate(*out);if(st==STATUS_SUCCESS)return st;}
 if(*out){if((*out)->State!=OAS_RETAINED){NTSTATUS close=OasAbortUnpublished(*out);if(close==STATUS_SUCCESS)*out=NULL;else (void)CghNativeRetainFailure(h,close);}else (void)CghNativeRetainFailure(h,st);return st;}
 /* No context/ownership move occurred; unwind the genuine still-owned cold
  * objects in reverse order. A failed step retains remaining caller objects. */
 NTSTATUS cleanup=STATUS_SUCCESS;if(*fault)cleanup=b->Api.DisconnectFaultUnpublished(b->Api.Interface.Context,&b->Native,fault);
 if(cleanup==STATUS_SUCCESS)cleanup=OpenLocalBankDisconnectUnpublished(b);
 if(cleanup==STATUS_SUCCESS)cleanup=CghNativeReleaseToReset(h);if(cleanup==STATUS_SUCCESS)cleanup=CghNativeLeave(h);
 if(cleanup!=STATUS_SUCCESS)(void)CghNativeRetainFailure(h,cleanup);return st;
}

NTSTATUS OasEnterFirmwareScope(OAS_BOOTSTRAP*a){if(!a||a->State!=OAS_ACTIVE||a->ColdConsumed)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=Begin(a);if(st==STATUS_SUCCESS){st=OsmaWitnessOwnedBindingHeld(&a->Native);if(st!=STATUS_SUCCESS)st=End(a,st);}if(st!=STATUS_SUCCESS){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);}return a->Status=st;}
NTSTATUS OasCurrentRuntime(OAS_BOOTSTRAP*a){
 if(!a||a->State!=OAS_ACTIVE||a->OperationThread!=PsGetCurrentThread()||!a->Scope.Token||a->Tables->Poisoned||a->Tables->Disabled||a->Tables->References<2||a->Tables->Session.Phase!=OSMA_ACTIVE)return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=a->ColdConsumed?CghNativeRuntimeCheck(a->Hold):CghNativeCheck(a->Hold);if(st!=STATUS_SUCCESS)return st;
 /* Tables were allocator-audited and made NC-visible before entering this
  * actual exclusive interval. This source path changes only data backing,
  * never PTEs or table ownership. Do not rescan the whole NC graph per word. */
 if(a->Native.Tables!=a->Tables||a->Tables->Tables.State!=OSMI_BUILT||a->Tables->Tables.PoolOrigin!=0x4e435047u||a->Tables->Tables.Config.table_physical!=a->Tables->Session.Image.ttbr0-((UINT64)a->BankIndex<<48))return STATUS_INVALID_DEVICE_STATE;
 return a->Bank->Api.CheckNs(a->Bank->Api.Interface.Context,&a->Bank->Native,a->Fault,a,&a->Scope);
}
NTSTATUS OasHandoffOwnedGbif(OAS_BOOTSTRAP*a){
 if(!a)return STATUS_INVALID_DEVICE_STATE;if(a->ColdConsumed||a->State!=OAS_ACTIVE||(!a->Hold->Hold.reset_mode&&a->Hold->Hold.before_halt))return a->Status=STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=OasCurrentRuntime(a);if(st==STATUS_SUCCESS)st=OsmaWitnessOwnedBindingHeld(&a->Native);
 if(st==STATUS_SUCCESS)st=a->Bank->Api.PromoteRuntime(a->Bank->Api.Interface.Context,&a->Bank->Native,a->Fault,a,&a->Scope,&a->Native);
 if(st!=STATUS_SUCCESS)return a->Status=st;
 /* Consume stopped/MMIO programming authority before either legacy owned-bit
  * release or the distinct cold-reset whole-device vendor boot-unhalt.
  * Failure never restores it or permits a cleanup retry. */
 a->ColdConsumed=TRUE;st=a->Hold->Hold.reset_mode?CghNativeUnhaltResetForBoot(a->Hold,a):CghNativeReleaseToReset(a->Hold);if(st==STATUS_SUCCESS)st=CghNativeCommitToBoot(a->Hold);if(st==STATUS_SUCCESS)st=OasCurrentRuntime(a);return a->Status=st;
}
NTSTATUS OasLeaveFirmwareScope(OAS_BOOTSTRAP*a,NTSTATUS result){if(!a||a->OperationThread!=PsGetCurrentThread())return STATUS_INVALID_DEVICE_STATE;NTSTATUS final=result;if(final==STATUS_SUCCESS)final=OasCurrentRuntime(a);if(final==STATUS_SUCCESS)final=OasMakeNcVisible(a->Tables);NTSTATUS st=End(a,final);if(st!=STATUS_SUCCESS){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);}return a->Status=st;}

NTSTATUS OasEnterRunningScope(OAS_BOOTSTRAP*a){if(!a||a->State!=OAS_ACTIVE||!a->ColdConsumed||!a->Hold->BootCommitted)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=Begin(a);if(st==STATUS_SUCCESS){st=OasCurrentRuntime(a);if(st!=STATUS_SUCCESS)st=End(a,st);}if(st!=STATUS_SUCCESS){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);}return a->Status=st;}

NTSTATUS OasColdActivateFromInactive(G321_INACTIVE_RUNTIME*r,CGH_NATIVE*h,OPEN_LOCAL_BANK_CLIENT*b,PVOID*fault,OAS_BOOTSTRAP**out){return OasColdActivateFromInactiveSetup(r,h,b,fault,out,NULL);}
