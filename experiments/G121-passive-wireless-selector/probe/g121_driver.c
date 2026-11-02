/* SPDX-License-Identifier: MIT
 * One-shot passive GPIO83 capture. Fixed address; no register writes, pin
 * configuration, clock/power requests, PCI access or source-selected ID IOCTL.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g121_binding.h"
#include "g121_protocol.h"
#include "g121_plan.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G121Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G121Control;
EVT_WDF_DEVICE_FILE_CREATE G121FileCreate;
static volatile LONG G121Attempts,G121Ready,G121Fault,G121Maps;
static volatile LONG64 G121Sequence;
static G121_CAPTURE*G121Frozen;
#include "guard-and-status.inc"

static int NoManagedRam(void)
{
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>MAXULONGLONG-start)break;
  if(start<G121_PAGE+4096&&G121_PAGE<start+n)break;
 }
 ExFreePool(ranges);return valid;
}
static ULONG Word(G121_CAPTURE*out,PVOID map,ULONG offset)
{
 KeMemoryBarrier();ULONG v=*(volatile const ULONG*)((const UCHAR*)map+offset);KeMemoryBarrier();out->ReadBytes+=4;return v;
}
static void Capture(G121_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 PVOID map=NULL;LARGE_INTEGER delay;PHYSICAL_ADDRESS address;
 Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!FullWindows()){out->Code=1001;goto done;}
 if(!NoManagedRam()){out->Code=1002;goto done;}
 if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
 address.QuadPart=G121_PAGE;out->MapCalls++;InterlockedIncrement(&G121Maps);
 map=MmMapIoSpaceEx(address,4096,PAGE_READONLY|PAGE_NOCACHE);
 if(!map){out->Code=1005;goto done;}
 for(ULONG pass=0;pass<2;pass++){
  if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
  out->Samples[pass][0]=Word(out,map,G121_CONTROL_OFFSET);
  if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
  out->Samples[pass][1]=Word(out,map,G121_INOUT_OFFSET);
  out->CompleteMask|=1u<<pass;
  if(!pass){delay.QuadPart=-500000;KeDelayExecutionThread(KernelMode,FALSE,&delay);}
 }
 if(!G121Qualified(out->Samples))out->Code=(out->Samples[0][0]&G121_UNSUITABLE_CONTROL||out->Samples[1][0]&G121_UNSUITABLE_CONTROL)?2001:2002;
 done:if(map)MmUnmapIoSpace(map,4096);
 out->End=KeQueryInterruptTime();if(out->Code)InterlockedExchange(&G121Fault,1);
 InterlockedExchange(&G121Ready,1);Status(&out->Status);
}
VOID G121Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G121_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G121_IOCTL_STATUS&&code!=G121_IOCTL_READ&&code!=G121_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G121_ABI||in.Magic!=G121_MAGIC||in.Reserved||in.Count||(code==G121_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G121_IOCTL_STATUS?sizeof(G121_STATUS):sizeof(G121_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G121_IOCTL_STATUS)Status(output);
 else if(code==G121_IOCTL_RESULT){if(!InterlockedCompareExchange(&G121Ready,0,0)||G121Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G121Frozen,sizeof(*G121Frozen));}
 else{if(InterlockedCompareExchange(&G121Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G121Frozen,sizeof(*G121Frozen));Capture(G121Frozen,request,in.Nonce);RtlCopyMemory(output,G121Frozen,sizeof(*G121Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
