/* SPDX-License-Identifier: MIT
 * One-shot passive root0 GCC/TLMM capture. Fixed addresses; no register writes, pin
 * configuration, clock/power requests, PCI access or source-selected ID IOCTL.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g125_binding.h"
#include "g125_protocol.h"
#include "g125_plan.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G125Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G125Control;
EVT_WDF_DEVICE_FILE_CREATE G125FileCreate;
static volatile LONG G125Attempts,G125Ready,G125Fault,G125Maps;
static volatile LONG64 G125Sequence;
static G125_CAPTURE*G125Frozen;
#include "guard-and-status.inc"

static int NoManagedRam(void)
{
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>MAXULONGLONG-start)break;
  for(ULONG j=0;j<G125_PAGE_COUNT;j++)if(start<G125Pages[j]+4096&&G125Pages[j]<start+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static ULONG Word(G125_CAPTURE*out,PVOID map,ULONG offset)
{
 KeMemoryBarrier();ULONG v=*(volatile const ULONG*)((const UCHAR*)map+offset);KeMemoryBarrier();out->ReadBytes+=4;return v;
}
static void Capture(G125_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 PVOID maps[G125_PAGE_COUNT]={0};LARGE_INTEGER delay;PHYSICAL_ADDRESS address;
 Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!FullWindows()){out->Code=1001;goto done;}
 if(!NoManagedRam()){out->Code=1002;goto done;}
 for(ULONG i=0;i<G125_PAGE_COUNT;i++){
  if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
  address.QuadPart=G125Pages[i];out->MapCalls++;InterlockedIncrement(&G125Maps);
  maps[i]=MmMapIoSpaceEx(address,4096,PAGE_READONLY|PAGE_NOCACHE);
  if(!maps[i]){out->Code=1005;goto done;}
 }
 for(ULONG pass=0;pass<2;pass++){
  for(ULONG i=0;i<G125_WORD_COUNT;i++){
   if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
   out->Samples[pass][i]=Word(out,maps[G125Words[i].Page],G125Words[i].Offset);
   out->WordMasks[pass]|=1u<<i;
  }
  out->CompleteMask|=1u<<pass;
  if(!pass){delay.QuadPart=-500000;KeDelayExecutionThread(KernelMode,FALSE,&delay);}
 }
 out->Code=G125SelectionCode(out->Samples);
 done:for(ULONG i=G125_PAGE_COUNT;i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],4096);
 out->End=KeQueryInterruptTime();if(out->Code)InterlockedExchange(&G125Fault,1);
 InterlockedExchange(&G125Ready,1);Status(&out->Status);
}
VOID G125Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G125_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G125_IOCTL_STATUS&&code!=G125_IOCTL_READ&&code!=G125_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G125_ABI||in.Magic!=G125_MAGIC||in.Reserved||in.Count||(code==G125_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G125_IOCTL_STATUS?sizeof(G125_STATUS):sizeof(G125_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G125_IOCTL_STATUS)Status(output);
 else if(code==G125_IOCTL_RESULT){if(!InterlockedCompareExchange(&G125Ready,0,0)||G125Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G125Frozen,sizeof(*G125Frozen));}
 else{if(InterlockedCompareExchange(&G125Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G125Frozen,sizeof(*G125Frozen));Capture(G125Frozen,request,in.Nonce);RtlCopyMemory(output,G125Frozen,sizeof(*G125Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
