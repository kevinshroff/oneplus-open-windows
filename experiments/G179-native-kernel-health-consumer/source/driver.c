/* SPDX-License-Identifier: MIT
 * One-shot read-only kernel consumer of two already-completed sensor results.
 * No MMIO mapping, physical read command, GLINK or charger-control interface.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g179_binding.h"
#include "provider_io.h"
#include "g179_protocol.h"
#include "abi-checks.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G179Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G179Control;
EVT_WDF_DEVICE_FILE_CREATE G179FileCreate;
static volatile LONG G179Attempts,G179Ready,G179Fault,G179Maps;
static volatile LONG64 G179Sequence;
static LONG G179Busy,G179Uncertain;
static G179_CAPTURE*G179Frozen;static WDFDEVICE G179Device;
#include "guard-and-status.inc"
static void Identity(G179_STATUS*s){Status(s);s->TransportUncertain=(ULONG)G179Uncertain;s->SafeToUnload=!G179Busy&&!G179Uncertain;}
static void Capture(G179_CAPTURE*out,ULONGLONG nonce)
{
 RtlZeroMemory(out,sizeof(*out));G179Busy=1;Identity(&out->Status);out->Nonce=nonce;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!WinPE()){out->Admission=1001;InterlockedExchange(&G179Fault,1);goto done;}
 ChReadKernelHealth(G179Device,nonce,0,0,CH_OBSERVE,&out->Result);
 if(out->Result.SentMask!=out->Result.ReceivedMask)G179Uncertain=1;
 if(!out->Result.Valid)InterlockedExchange(&G179Fault,1);
 done:G179Busy=0;InterlockedExchange(&G179Ready,1);Identity(&out->Status);
}
VOID G179Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G179_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G179_IOCTL_STATUS&&code!=G179_IOCTL_READ&&code!=G179_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G179_ABI||in.Magic!=G179_MAGIC||in.Reserved||in.Count||(code==G179_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G179_IOCTL_STATUS?sizeof(G179_STATUS):sizeof(G179_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G179_IOCTL_STATUS)Identity(output);
 else if(code==G179_IOCTL_RESULT){if(!InterlockedCompareExchange(&G179Ready,0,0)||G179Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G179Frozen,sizeof(*G179Frozen));}
 else{if(InterlockedCompareExchange(&G179Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}Capture(G179Frozen,in.Nonce);RtlCopyMemory(output,G179Frozen,sizeof(*G179Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
