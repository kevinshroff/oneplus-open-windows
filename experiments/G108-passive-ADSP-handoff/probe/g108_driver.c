/* SPDX-License-Identifier: MIT
 * Demand-loaded, one-shot passive firmware/shared-memory observer.
 * All maps are READONLY. No register/SMEM/SCM/charger/DSP write callback exists.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g108_binding.h"
#include "g108_protocol.h"
#include "g108_select.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G108Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G108Control;
EVT_WDF_DEVICE_FILE_CREATE G108FileCreate;
static volatile LONG G108Attempts,G108Ready,G108Fault,G108Maps;
static volatile LONG64 G108Sequence;
static G108_CAPTURE*G108Frozen;
#include "guard-and-status.inc"

/* Firmware reservations, not caller-selected addresses. SMEM/IMEM are uncached;
 * the installed PrePi table marks XBL DT and the runtime log as write-back.
 * Reject OS-managed physical RAM before mapping. */
static int ReservedRam(void)
{
 const ULONGLONG bases[]={0x81a00000ULL,0x81d00000ULL,0xa7605000ULL};
 const ULONGLONG lengths[]={0x40000ULL,0x200000ULL,0x8000ULL};
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}
  if(n>MAXULONGLONG-start)break;
  for(ULONG j=0;j<3;j++)if(start<bases[j]+lengths[j]&&bases[j]<start+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static int Add(G108_CAPTURE*out,ULONGLONG at,ULONG bytes,ULONG kind,ULONG h0,ULONG h1)
{
 ULONG n=out->RegionCount;if(n>=7||!bytes||bytes>G108_PART_LIMIT||out->PayloadBytes>G108_PAYLOAD||2*bytes>G108_PAYLOAD-out->PayloadBytes)return 0;
 out->Regions[n]=(G108_REGION){at,bytes,out->PayloadBytes,h0,h1,kind,0};out->RegionCount++;
 out->PayloadBytes+=2*bytes;return 1;
}
static int CopyRegion(G108_CAPTURE*out,ULONG index,ULONG pass,WDFREQUEST request)
{
 G108_REGION*r=out->Regions+index;PHYSICAL_ADDRESS a;PVOID map;ULONGLONG begin=r->Address&~4095ULL;
 SIZE_T delta=(SIZE_T)(r->Address-begin),length=(delta+r->Bytes+4095)&~(SIZE_T)4095;
 if(WdfRequestIsCanceled(request)){r->Status=1;return 0;}
 a.QuadPart=(LONGLONG)begin;out->MapCalls++;InterlockedIncrement(&G108Maps);
 map=MmMapIoSpaceEx(a,length,PAGE_READONLY|((r->Kind==3||r->Kind==4)?0:PAGE_NOCACHE));
 if(!map){r->Status=2;return 0;}
 volatile const UCHAR*src=(volatile const UCHAR*)map+delta;
 UCHAR*dst=out->Payload+r->Offset+pass*r->Bytes;
 KeMemoryBarrier();for(ULONG i=0;i<r->Bytes;i++)dst[i]=src[i];KeMemoryBarrier();
 MmUnmapIoSpace(map,length);out->ReadBytes+=r->Bytes;
 if(pass)out->CompleteMask|=1u<<index;return 1;
}
static void Capture(G108_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 G108_PART parts[2];uint32_t count=0;LARGE_INTEGER delay;
 Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!FullWindows()){out->Code=1001;goto done;}
 if(!ReservedRam()){out->Code=1002;goto done;}
 if(!Add(out,0x81d00000,0x3000,1,0,0)||!Add(out,0x81eff000,0x1000,2,0,0)||
 !Add(out,0x81a00000,0x40000,3,0,0)||!Add(out,0xa7605000,0x8000,4,0,0)||
 !Add(out,0x146aa94c,200,5,0,0)){out->Code=1003;goto done;}
 for(ULONG i=0;i<5;i++)if(!CopyRegion(out,i,0,request)){out->Code=1004;goto done;}
 out->Code=(ULONG)G108Select(out->Payload+out->Regions[1].Offset,4096,parts,&count);
 if(out->Code){out->Code+=2000;goto done;}
 for(ULONG i=0;i<count;i++){
  if(!Add(out,0x81d00000ULL+parts[i].Offset,parts[i].Bytes,6,parts[i].Host0,parts[i].Host1)||!CopyRegion(out,5+i,0,request)){out->Code=1005;goto done;}
  if(!G108PartHeader(out->Payload+out->Regions[5+i].Offset,parts+i)){out->Code=1006;goto done;}
 }
 delay.QuadPart=-1000000;KeDelayExecutionThread(KernelMode,FALSE,&delay);
 for(ULONG i=0;i<out->RegionCount;i++)if(!CopyRegion(out,i,1,request)){out->Code=1007;goto done;}
 if(RtlCompareMemory(out->Payload+out->Regions[1].Offset,out->Payload+out->Regions[1].Offset+4096,4096)!=4096){out->Code=1008;goto done;}
 for(ULONG i=0;i<count;i++)if(!G108PartHeader(out->Payload+out->Regions[5+i].Offset+parts[i].Bytes,parts+i)){out->Code=1009;goto done;}
 done:out->End=KeQueryInterruptTime();if(out->Code)InterlockedExchange(&G108Fault,1);
 InterlockedExchange(&G108Ready,1);Status(&out->Status);
}
VOID G108Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G108_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G108_IOCTL_STATUS&&code!=G108_IOCTL_READ&&code!=G108_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G108_ABI||in.Magic!=G108_MAGIC||in.Reserved||in.Count||(code==G108_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G108_IOCTL_STATUS?sizeof(G108_STATUS):sizeof(G108_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G108_IOCTL_STATUS)Status(output);
 else if(code==G108_IOCTL_RESULT){if(!InterlockedCompareExchange(&G108Ready,0,0)||G108Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G108Frozen,sizeof(*G108Frozen));}
 else{if(InterlockedCompareExchange(&G108Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G108Frozen,sizeof(*G108Frozen));Capture(G108Frozen,request,in.Nonce);RtlCopyMemory(output,G108Frozen,sizeof(*G108Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
