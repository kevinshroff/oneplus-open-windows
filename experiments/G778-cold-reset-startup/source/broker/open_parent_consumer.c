#include "open_parent_consumer.h"
BOOLEAN OpenExactHardwareId(PDEVICE_OBJECT p,PCWSTR wanted){
 WCHAR ids[256];ULONG used=0;UNICODE_STRING expected;RtlInitUnicodeString(&expected,wanted);
 NTSTATUS s=IoGetDeviceProperty(p,DevicePropertyHardwareID,sizeof(ids),ids,&used);
 if(s!=STATUS_SUCCESS||used<4||used>sizeof(ids)||(used&1)||ids[used/2-1]||ids[used/2-2])return FALSE;
 for(ULONG a=0;a<used/2-1&&ids[a];){ULONG end=a;while(end<used/2&&ids[end])end++;if(end==used/2)return FALSE;
  UNICODE_STRING id;id.Buffer=ids+a;id.Length=(USHORT)((end-a)*2);id.MaximumLength=id.Length;
  if(RtlEqualUnicodeString(&id,&expected,TRUE))return TRUE;a=end+1;
 }return FALSE;
}
static NTSTATUS Complete(PDEVICE_OBJECT d,PIRP i,PVOID event){UNREFERENCED_PARAMETER(d);UNREFERENCED_PARAMETER(i);KeSetEvent(event,IO_NO_INCREMENT,FALSE);return STATUS_MORE_PROCESSING_REQUIRED;}
static NTSTATUS Query(PDEVICE_OBJECT d,OPEN_PARENT_INTERFACE*out){
 PIRP i=IoAllocateIrp(d->StackSize,FALSE);if(!i)return STATUS_INSUFFICIENT_RESOURCES;
 KEVENT event;KeInitializeEvent(&event,NotificationEvent,FALSE);i->IoStatus.Status=STATUS_NOT_SUPPORTED;
 PIO_STACK_LOCATION sp=IoGetNextIrpStackLocation(i);sp->MajorFunction=IRP_MJ_PNP;sp->MinorFunction=IRP_MN_QUERY_INTERFACE;
 sp->Parameters.QueryInterface.InterfaceType=&OpenParentQueryGuid;sp->Parameters.QueryInterface.Size=sizeof(*out);sp->Parameters.QueryInterface.Version=OPEN_PARENT_VERSION;sp->Parameters.QueryInterface.Interface=(PINTERFACE)out;sp->Parameters.QueryInterface.InterfaceSpecificData=NULL;
 IoSetCompletionRoutine(i,Complete,&event,TRUE,TRUE,TRUE);NTSTATUS st=IoCallDriver(d,i);
 if(st==STATUS_PENDING)KeWaitForSingleObject(&event,Executive,KernelMode,FALSE,NULL);
 st=i->IoStatus.Status;IoFreeIrp(i);return st;
}
NTSTATUS OpenParentBind(OPEN_PARENT_BINDING*b){
 if(!b||b->Bound||b->File||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 PWSTR list=NULL;NTSTATUS st=IoGetDeviceInterfaces(&OpenOpbmDeviceGuid,NULL,0,&list);if(st!=STATUS_SUCCESS)return st;
 ULONG n=0;while(n<32767&&list[n])n++;if(!n||n==32767||list[n+1]){ExFreePool(list);return STATUS_OBJECT_NAME_COLLISION;}
 UNICODE_STRING name;RtlInitUnicodeString(&name,list);PDEVICE_OBJECT target=NULL;
 st=IoGetDeviceObjectPointer(&name,FILE_READ_DATA,&b->File,&target);ExFreePool(list);if(st!=STATUS_SUCCESS)return st;
 RtlZeroMemory(&b->Api,sizeof(b->Api));st=Query(target,&b->Api);
 if(st!=STATUS_SUCCESS){ObDereferenceObject(b->File);b->File=NULL;return st;}
 if(b->Api.Interface.Size!=sizeof(b->Api)||b->Api.Interface.Version!=OPEN_PARENT_VERSION||!b->Api.Interface.Context||!b->Api.Interface.InterfaceReference||!b->Api.Interface.InterfaceDereference||!b->Api.ReadCurrent||!b->Api.ProviderPdo||b->Api.PhysicalBase!=0x152000||b->Api.Bytes!=0x1000||b->Api.ReadOnly!=1||!OpenExactHardwareId(b->Api.ProviderPdo,L"ACPI\\OPEN0182")){
  /* A successful QUERY owns one reference. Missing release ABI is uncertain:
   * keep the file/interface context resident rather than guessing cleanup. */
  /* Unknown successful ABI is retained; never invoke an unqualified pointer. */
  return STATUS_DEVICE_CONFIGURATION_ERROR;
 }
 b->Bound=TRUE;ULONG external,ap;st=OpenParentRead(b,&external,&ap);
 if(st!=STATUS_SUCCESS)OpenParentUnbind(b);return st;
}
NTSTATUS OpenParentRead(OPEN_PARENT_BINDING*b,ULONG*external,ULONG*ap){
 if(!b||!b->Bound||!external||!ap||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 OPEN_PARENT_SNAPSHOT v;RtlZeroMemory(&v,sizeof(v));ULONGLONG begin=KeQueryInterruptTime();NTSTATUS st=b->Api.ReadCurrent(b->Api.Interface.Context,&v);ULONGLONG end=KeQueryInterruptTime();
 if(st!=STATUS_SUCCESS)return st;
 if(v.Status!=STATUS_SUCCESS||v.Size!=sizeof(v)||v.Version!=OPEN_PARENT_VERSION||v.Magic!=OPEN_PARENT_MAGIC||v.Reserved||!v.Instance||!v.PrepareEpoch||!v.D0Epoch||v.At100ns<begin||v.At100ns>end||v.ExternalVote==MAXULONG||v.ApVote==MAXULONG)return STATUS_DEVICE_DATA_ERROR;
 if(b->Instance&&(v.Instance!=b->Instance||v.PrepareEpoch!=b->PrepareEpoch||v.D0Epoch!=b->D0Epoch))return STATUS_INVALID_DEVICE_STATE;
 b->Instance=v.Instance;b->PrepareEpoch=v.PrepareEpoch;b->D0Epoch=v.D0Epoch;*external=v.ExternalVote;*ap=v.ApVote;return STATUS_SUCCESS;
}
VOID OpenParentUnbind(OPEN_PARENT_BINDING*b){if(b->Bound){b->Api.Interface.InterfaceDereference(b->Api.Interface.Context);ObDereferenceObject(b->File);RtlZeroMemory(b,sizeof(*b));}}
