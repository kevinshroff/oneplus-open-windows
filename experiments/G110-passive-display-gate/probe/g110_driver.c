/* SPDX-License-Identifier: MIT
 * One-shot, fixed passive DPU inspection. No writable mapping or hardware write.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g110_binding.h"
#include "g110_protocol.h"
#include "g110_plan.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G110Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G110Control;
EVT_WDF_DEVICE_FILE_CREATE G110FileCreate;
static volatile LONG G110Attempts,G110Ready,G110Fault,G110Maps;
static volatile LONG64 G110Sequence;
static G110_CAPTURE*G110Frozen;
#include "guard-and-status.inc"

static int NoManagedRam(void)
{
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>MAXULONGLONG-start)break;
  for(ULONG j=0;j<G110_PAGES;j++)if(start<G110Plan[j].Page+4096&&G110Plan[j].Page<start+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static ULONG Word(G110_CAPTURE*out,PVOID map,ULONG offset)
{
 KeMemoryBarrier();ULONG v=*(volatile const ULONG*)((const UCHAR*)map+offset);KeMemoryBarrier();out->ReadBytes+=4;return v;
}
static void Store(G110_CAPTURE*out,ULONG index,ULONG pass,PVOID map)
{
 G110_REGION*r=out->Regions+index;ULONG*dst=(ULONG*)(out->Payload+r->Offset+pass*r->Bytes);
 for(ULONG j=0;j<G110Plan[index].Count;j++)dst[j]=Word(out,map,G110Plan[index].Off[j]);
 r->Status|=1u<<pass;
 if(pass)out->CompleteMask|=1u<<index;
}
static int Gates(G110_CAPTURE*out,PVOID*maps)
{
 unsigned a[3],b[2],c[2],d[2];
 for(ULONG i=0;i<3;i++)a[i]=Word(out,maps[0],G110Plan[0].Off[i]);
 for(ULONG i=0;i<2;i++){b[i]=Word(out,maps[1],G110Plan[1].Off[i]);c[i]=Word(out,maps[2],G110Plan[2].Off[i]);d[i]=Word(out,maps[3],G110Plan[3].Off[i]);}
 return G110Gate(a,b,c,d);
}
static PVOID Map(G110_CAPTURE*out,ULONG index)
{
 PHYSICAL_ADDRESS a;a.QuadPart=(LONGLONG)G110Plan[index].Page;out->MapCalls++;InterlockedIncrement(&G110Maps);
 return MmMapIoSpaceEx(a,4096,PAGE_READONLY|PAGE_NOCACHE);
}
static void Capture(G110_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 PVOID clocks[4]={0};LARGE_INTEGER delay;ULONG offset=0;
 Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!FullWindows()){out->Code=1001;goto done;}
 if(!NoManagedRam()){out->Code=1002;goto done;}
 for(ULONG i=0;i<G110_PAGES;i++){
  ULONG bytes=G110Plan[i].Count*4;if(i>=20||offset+2*bytes>G110_PAYLOAD){out->Code=1003;goto done;}
  out->Regions[i]=(G110_REGION){G110Plan[i].Page,bytes,offset,0,0,i,0};offset+=2*bytes;out->RegionCount++;
 }
 out->PayloadBytes=offset;
 for(ULONG i=0;i<4;i++){
  if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
  clocks[i]=Map(out,i);if(!clocks[i]){out->Code=1005;goto done;}
 }
 for(ULONG pass=0;pass<2;pass++){
  for(ULONG i=0;i<4;i++)Store(out,i,pass,clocks[i]);
  if(!Gates(out,clocks)){out->Code=2001;goto done;}
  for(ULONG i=4;i<G110_PAGES;i++){
   if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
   if(!Gates(out,clocks)){out->Code=2002;goto done;}
   PVOID map=Map(out,i);if(!map){out->Code=1005;goto done;}
   Store(out,i,pass,map);MmUnmapIoSpace(map,4096);
   if(i==4){ULONG v=*(ULONG*)(out->Payload+out->Regions[i].Offset+pass*4);if((v&0xffff0000u)!=0x90000000u){out->Code=2003;goto done;}}
  }
  if(!Gates(out,clocks)){out->Code=2004;goto done;}
  if(!pass){delay.QuadPart=-500000;KeDelayExecutionThread(KernelMode,FALSE,&delay);}
 }
 done:for(ULONG i=0;i<4;i++)if(clocks[i])MmUnmapIoSpace(clocks[i],4096);
 out->End=KeQueryInterruptTime();if(out->Code)InterlockedExchange(&G110Fault,1);
 InterlockedExchange(&G110Ready,1);Status(&out->Status);
}
VOID G110Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G110_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G110_IOCTL_STATUS&&code!=G110_IOCTL_READ&&code!=G110_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G110_ABI||in.Magic!=G110_MAGIC||in.Reserved||in.Count||(code==G110_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G110_IOCTL_STATUS?sizeof(G110_STATUS):sizeof(G110_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G110_IOCTL_STATUS)Status(output);
 else if(code==G110_IOCTL_RESULT){if(!InterlockedCompareExchange(&G110Ready,0,0)||G110Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G110Frozen,sizeof(*G110Frozen));}
 else{if(InterlockedCompareExchange(&G110Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G110Frozen,sizeof(*G110Frozen));Capture(G110Frozen,request,in.Nonce);RtlCopyMemory(output,G110Frozen,sizeof(*G110Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
