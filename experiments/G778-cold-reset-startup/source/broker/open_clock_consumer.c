#include "open_clock_consumer.h"
#include "open_parent_consumer.h"
static NTSTATUS Complete(PDEVICE_OBJECT d,PIRP i,PVOID event){UNREFERENCED_PARAMETER(d);UNREFERENCED_PARAMETER(i);KeSetEvent(event,IO_NO_INCREMENT,FALSE);return STATUS_MORE_PROCESSING_REQUIRED;}
static NTSTATUS Query(PDEVICE_OBJECT d,OPEN_CLOCK_INTERFACE*out){
 PIRP i=IoAllocateIrp(d->StackSize,FALSE);if(!i)return STATUS_INSUFFICIENT_RESOURCES;
 KEVENT event;KeInitializeEvent(&event,NotificationEvent,FALSE);i->IoStatus.Status=STATUS_NOT_SUPPORTED;
 PIO_STACK_LOCATION sp=IoGetNextIrpStackLocation(i);sp->MajorFunction=IRP_MJ_PNP;sp->MinorFunction=IRP_MN_QUERY_INTERFACE;
 sp->Parameters.QueryInterface.InterfaceType=&OpenClockQueryGuid;sp->Parameters.QueryInterface.Size=sizeof(*out);sp->Parameters.QueryInterface.Version=OPEN_CLOCK_VERSION;sp->Parameters.QueryInterface.Interface=(PINTERFACE)out;sp->Parameters.QueryInterface.InterfaceSpecificData=NULL;
 IoSetCompletionRoutine(i,Complete,&event,TRUE,TRUE,TRUE);NTSTATUS st=IoCallDriver(d,i);
 if(st==STATUS_PENDING)KeWaitForSingleObject(&event,Executive,KernelMode,FALSE,NULL);
 st=i->IoStatus.Status;IoFreeIrp(i);return st;
}
NTSTATUS OpenClockOpen(OPEN_CLOCK_BINDING*b){
 if(!b||b->Bound||b->File||b->Token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 PWSTR list=NULL;NTSTATUS st=IoGetDeviceInterfaces(&OpenClockDeviceGuid,NULL,0,&list);if(st!=STATUS_SUCCESS)return st;
 ULONG n=0;while(n<32767&&list[n])n++;if(!n||n==32767||list[n+1]){ExFreePool(list);return STATUS_OBJECT_NAME_COLLISION;}
 UNICODE_STRING name;RtlInitUnicodeString(&name,list);PDEVICE_OBJECT target=NULL;
 st=IoGetDeviceObjectPointer(&name,FILE_READ_DATA,&b->File,&target);ExFreePool(list);if(st!=STATUS_SUCCESS)return st;
 RtlZeroMemory(&b->Api,sizeof(b->Api));st=Query(target,&b->Api);
 if(st!=STATUS_SUCCESS){ObDereferenceObject(b->File);b->File=NULL;return st;}
 if(b->Api.Interface.Size!=sizeof(b->Api)||b->Api.Interface.Version!=OPEN_CLOCK_VERSION||!b->Api.Interface.Context||!b->Api.Interface.InterfaceReference||!b->Api.Interface.InterfaceDereference||!b->Api.ProviderPdo||!b->Api.Acquire||!b->Api.Release||!b->Api.Snapshot||!b->Api.InspectGlobals||!OpenExactHardwareId(b->Api.ProviderPdo,L"ACPI\\OPEN0D01"))return STATUS_DEVICE_CONFIGURATION_ERROR; /* retain unknown successful ABI */
 b->Bound=TRUE;return STATUS_SUCCESS;
}
NTSTATUS OpenClockConnect(OPEN_CLOCK_BINDING*b,const OPEN_CLOCK_CLIENT*c){
 if(!c)return STATUS_INVALID_PARAMETER;NTSTATUS st=OpenClockOpen(b);if(st!=STATUS_SUCCESS)return st;
 st=b->Api.Acquire(b->Api.Interface.Context,c,&b->Token);
 if(st!=STATUS_SUCCESS){if(!b->Token)(void)OpenClockClose(b);return st;}
 if(!b->Token)return STATUS_DEVICE_DATA_ERROR;return STATUS_SUCCESS;
}
NTSTATUS OpenClockClose(OPEN_CLOCK_BINDING*b){
 if(!b||!b->Bound||b->Token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 b->Api.Interface.InterfaceDereference(b->Api.Interface.Context);ObDereferenceObject(b->File);RtlZeroMemory(b,sizeof(*b));return STATUS_SUCCESS;
}

NTSTATUS OpenClockDisconnect(OPEN_CLOCK_BINDING*b){
 if(!b||!b->Bound||!b->Token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=b->Api.Release(b->Api.Interface.Context,b->Token);if(st!=STATUS_SUCCESS)return st;
 b->Api.Interface.InterfaceDereference(b->Api.Interface.Context);ObDereferenceObject(b->File);RtlZeroMemory(b,sizeof(*b));return STATUS_SUCCESS;
}
