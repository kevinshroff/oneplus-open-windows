#include <ntddk.h>
#include <wdmsec.h>
#include "query_protocol.h"
C_ASSERT(sizeof(G1268_QUERY_REQUEST)==8);
C_ASSERT(FIELD_OFFSET(G1268_MONITOR_FRAME,Entries)==64);
C_ASSERT(FIELD_OFFSET(G1268_MONITOR_FRAME,Returns)==72);
C_ASSERT(FIELD_OFFSET(G1268_MONITOR_FRAME,Interrupted)==80);
C_ASSERT(sizeof(G1268_MONITOR_FRAME)==88);
C_ASSERT(sizeof(G1268_REPORT)==184);
void G1268SmcFastInfo(G1268_MONITOR_FRAME *Frame);
static const GUID DeviceClass={0x64841268,0xb417,0x4310,{0xaa,0x15,0x63,0x4c,0x0b,0xee,0x12,0x68}};
typedef struct {
 KMUTEX CallGate;KSPIN_LOCK StateLock;EX_RUNDOWN_REF Rundown;
 PIO_WORKITEM Work;G1268_REPORT Report;G1268_MONITOR_FRAME Retained;
} G1268_DEVICE_CONTEXT;
static NTSTATUS Complete(PIRP Irp,NTSTATUS S,ULONG_PTR Bytes){Irp->IoStatus.Status=S;Irp->IoStatus.Information=Bytes;IoCompleteRequest(Irp,IO_NO_INCREMENT);return S;}
static NTSTATUS OpenClose(PDEVICE_OBJECT Device,PIRP Irp){UNREFERENCED_PARAMETER(Device);return Complete(Irp,STATUS_SUCCESS,0);}
static NTSTATUS Refuse(PDEVICE_OBJECT Device,PIRP Irp){UNREFERENCED_PARAMETER(Device);return Complete(Irp,STATUS_INVALID_DEVICE_REQUEST,0);}
static VOID Worker(PDEVICE_OBJECT Device,PVOID Parameter){
 G1268_DEVICE_CONTEXT *C=Device->DeviceExtension;PIRP Irp=Parameter;KIRQL Old;BOOLEAN Begin,Retain;
 /* IoQueueWorkItem guarantees PASSIVE; no monitor invocation at another IRQL. */
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL){
  KeAcquireSpinLock(&C->StateLock,&Old);C->Report.State=G1268_INCOMPLETE_RETAINED;C->Report.Flags|=G1268_F_RETAINED;
  RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,&C->Report,sizeof(C->Report));KeReleaseSpinLock(&C->StateLock,Old);
  Complete(Irp,STATUS_SUCCESS,sizeof(G1268_REPORT));return; /* rundown intentionally retained */
 }
 KeWaitForSingleObject(&C->CallGate,Executive,KernelMode,FALSE,NULL);
 KeAcquireSpinLock(&C->StateLock,&Old);Begin=(BOOLEAN)G1268Begin(&C->Report);KeReleaseSpinLock(&C->StateLock,Old);
 if(!Begin){KeReleaseMutex(&C->CallGate,FALSE);ExReleaseRundownProtection(&C->Rundown);Complete(Irp,STATUS_INVALID_DEVICE_STATE,0);return;}
 RtlZeroMemory(&C->Retained,sizeof(C->Retained));
 /* Only explicit once IOCTL reaches this REAL thunk. No lock/IRQL spin region is held. */
 G1268SmcFastInfo(&C->Retained);
 KeAcquireSpinLock(&C->StateLock,&Old);G1268Finish(&C->Report,&C->Retained);
 Retain=(BOOLEAN)(C->Report.State==G1268_INCOMPLETE_RETAINED);
 RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,&C->Report,sizeof(C->Report));KeReleaseSpinLock(&C->StateLock,Old);
 KeReleaseMutex(&C->CallGate,FALSE);
 if(!Retain)ExReleaseRundownProtection(&C->Rundown); /* positive/unknown retains all state until reboot */
 Complete(Irp,STATUS_SUCCESS,sizeof(G1268_REPORT));
}
static NTSTATUS Control(PDEVICE_OBJECT Device,PIRP Irp){
 G1268_DEVICE_CONTEXT *C=Device->DeviceExtension;PIO_STACK_LOCATION S=IoGetCurrentIrpStackLocation(Irp);KIRQL Old;BOOLEAN Accepted;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Complete(Irp,STATUS_INVALID_DEVICE_STATE,0);
 if(S->Parameters.DeviceIoControl.OutputBufferLength<sizeof(G1268_REPORT)||!Irp->AssociatedIrp.SystemBuffer)return Complete(Irp,STATUS_BUFFER_TOO_SMALL,0);
 ULONG Code=S->Parameters.DeviceIoControl.IoControlCode;
 if(Code==G1268_IOCTL_STATUS){
  if(S->Parameters.DeviceIoControl.InputBufferLength)return Complete(Irp,STATUS_INVALID_PARAMETER,0);
  /* Report snapshot never reads a partially written raw frame or issues a call. */
  KeAcquireSpinLock(&C->StateLock,&Old);RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,&C->Report,sizeof(C->Report));KeReleaseSpinLock(&C->StateLock,Old);
  return Complete(Irp,STATUS_SUCCESS,sizeof(G1268_REPORT));
 }
 if(Code!=G1268_IOCTL_QUERY_ONCE||S->Parameters.DeviceIoControl.InputBufferLength!=sizeof(G1268_QUERY_REQUEST))return Complete(Irp,STATUS_INVALID_DEVICE_REQUEST,0);
 G1268_QUERY_REQUEST Request;RtlCopyMemory(&Request,Irp->AssociatedIrp.SystemBuffer,sizeof(Request));
 if(Request.Version!=G1268_VERSION||Request.Tag!=G1268_QUERY_TAG)return Complete(Irp,STATUS_INVALID_PARAMETER,0);
 if(!ExAcquireRundownProtection(&C->Rundown))return Complete(Irp,STATUS_DELETE_PENDING,0);
 KeAcquireSpinLock(&C->StateLock,&Old);Accepted=(BOOLEAN)G1268Accept(&C->Report);KeReleaseSpinLock(&C->StateLock,Old);
 if(!Accepted){ExReleaseRundownProtection(&C->Rundown);return Complete(Irp,STATUS_INVALID_DEVICE_STATE,0);}
 /* No cancellation routine can abort a dispatched SMC. Caller timeout is not cancellation. */
 IoMarkIrpPending(Irp);IoQueueWorkItem(C->Work,Worker,DelayedWorkQueue,Irp);return STATUS_PENDING;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver,PUNICODE_STRING RegistryPath){
 UNREFERENCED_PARAMETER(RegistryPath);UNICODE_STRING Name,Link,Sddl;PDEVICE_OBJECT Device=NULL;NTSTATUS St;
 RtlInitUnicodeString(&Name,L"\\Device\\OpenGpuScmQueryG1268");RtlInitUnicodeString(&Link,L"\\DosDevices\\OpenGpuScmQueryG1268");
 RtlInitUnicodeString(&Sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 St=IoCreateDeviceSecure(Driver,sizeof(G1268_DEVICE_CONTEXT),&Name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&Sddl,&DeviceClass,&Device);
 if(!NT_SUCCESS(St))return St;
 G1268_DEVICE_CONTEXT *C=Device->DeviceExtension;RtlZeroMemory(C,sizeof(*C));KeInitializeMutex(&C->CallGate,0);KeInitializeSpinLock(&C->StateLock);ExInitializeRundownProtection(&C->Rundown);G1268Initialize(&C->Report);
 C->Work=IoAllocateWorkItem(Device);if(!C->Work){IoDeleteDevice(Device);return STATUS_INSUFFICIENT_RESOURCES;}
 for(ULONG I=0;I<=IRP_MJ_MAXIMUM_FUNCTION;I++)Driver->MajorFunction[I]=Refuse;
 Driver->MajorFunction[IRP_MJ_CREATE]=OpenClose;Driver->MajorFunction[IRP_MJ_CLOSE]=OpenClose;Driver->MajorFunction[IRP_MJ_CLEANUP]=OpenClose;Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=Control;
 /* Intentionally resident for this boot: no unload/reload route can replay the query. */
 Driver->DriverUnload=NULL;Device->Flags|=DO_BUFFERED_IO;
 St=IoCreateSymbolicLink(&Link,&Name);if(!NT_SUCCESS(St)){IoFreeWorkItem(C->Work);IoDeleteDevice(Device);return St;}
 Device->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS; /* no monitor call on load */
}
