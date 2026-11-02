#include "local_bank_interface.h"
#include "broker/open_parent_consumer.h"
static NTSTATUS Done(PDEVICE_OBJECT d,PIRP i,PVOID c){UNREFERENCED_PARAMETER(d);UNREFERENCED_PARAMETER(i);KeSetEvent(c,IO_NO_INCREMENT,FALSE);return STATUS_MORE_PROCESSING_REQUIRED;}
NTSTATUS OpenLocalBankConnect(OPEN_LOCAL_BANK_CLIENT*b,CGH_NATIVE*h){
 if(!b||b->Bound||b->QuerySucceeded||b->Native.Referenced||!h||!h->Clock.File||!h->Clock.Token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=CghNativeCheck(h);if(st!=STATUS_SUCCESS)return st;b->Hold=h;
 PDEVICE_OBJECT fdo=IoGetRelatedDeviceObject(h->Clock.File);PIRP i=IoAllocateIrp(fdo->StackSize,FALSE);if(!i)return STATUS_INSUFFICIENT_RESOURCES;KEVENT e;KeInitializeEvent(&e,NotificationEvent,FALSE);i->IoStatus.Status=STATUS_NOT_SUPPORTED;
 PIO_STACK_LOCATION sp=IoGetNextIrpStackLocation(i);sp->MajorFunction=IRP_MJ_PNP;sp->MinorFunction=IRP_MN_QUERY_INTERFACE;sp->Parameters.QueryInterface.InterfaceType=&OpenLocalBankQueryGuid;sp->Parameters.QueryInterface.Size=sizeof(b->Api);sp->Parameters.QueryInterface.Version=6;sp->Parameters.QueryInterface.Interface=(PINTERFACE)&b->Api;sp->Parameters.QueryInterface.InterfaceSpecificData=NULL;
 IoSetCompletionRoutine(i,Done,&e,TRUE,TRUE,TRUE);st=IoCallDriver(fdo,i);if(st==STATUS_PENDING)KeWaitForSingleObject(&e,Executive,KernelMode,FALSE,NULL);st=i->IoStatus.Status;IoFreeIrp(i);if(st!=STATUS_SUCCESS)return st;b->QuerySucceeded=TRUE;
 if(b->Api.Interface.Size!=sizeof(b->Api)||b->Api.Interface.Version!=6||!b->Api.Interface.Context||!b->Api.Interface.InterfaceReference||!b->Api.Interface.InterfaceDereference||b->Api.ProviderPdo!=h->Clock.Api.ProviderPdo||!OpenExactHardwareId(b->Api.ProviderPdo,L"ACPI\\OPEN0D01")||!b->Api.Reserve||!b->Api.Qualify||!b->Api.BindRequest||!b->Api.CheckBank||!b->Api.PinProgramming||!b->Api.ReleaseUnpublished||!b->Api.ConnectFault||!b->Api.CheckFault||!b->Api.DisconnectFaultUnpublished||!b->Api.EnterNs||!b->Api.CheckNs||!b->Api.LeaveNs||!b->Api.PromoteRuntime||!b->Api.CheckNsFast||!b->Api.ReserveGpuUser||!b->Api.CheckGpuUser||!b->Api.ReleaseGpuUserUnpublished||!b->Api.PinGpuProgramming||!b->Api.CommitGpuProgramming)return STATUS_DEVICE_CONFIGURATION_ERROR; /* unknown success: retain interface/Hold, never guess cleanup */
 b->Bound=TRUE;st=b->Api.Reserve(b->Api.Interface.Context,&b->Native,h);if(st==STATUS_SUCCESS&&(!b->Native.Referenced||!b->Native.Id||!b->Native.Fdo||!b->Native.Generation||!b->Native.StopSerial))return STATUS_DEVICE_DATA_ERROR; /* retain inconsistent successful output */
 if(st!=STATUS_SUCCESS&&!b->Native.Referenced&&!b->Native.Id&&!b->Native.Fdo){b->Api.Interface.InterfaceDereference(b->Api.Interface.Context);RtlZeroMemory(b,sizeof(*b));}return st;
}
NTSTATUS OpenLocalBankDisconnectUnpublished(OPEN_LOCAL_BANK_CLIENT*b){
 if(!b||!b->Bound||!b->QuerySucceeded||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=b->Api.ReleaseUnpublished(b->Api.Interface.Context,&b->Native);if(st!=STATUS_SUCCESS)return st;b->Api.Interface.InterfaceDereference(b->Api.Interface.Context);RtlZeroMemory(b,sizeof(*b));return STATUS_SUCCESS;
}
