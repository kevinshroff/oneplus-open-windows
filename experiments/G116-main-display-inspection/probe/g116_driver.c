/* SPDX-License-Identifier: MIT
 * One-shot, fixed passive DPU inspection. No writable mapping or hardware write.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g116_binding.h"
#include "g116_protocol.h"
#include "g116_plan.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G116Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G116Control;
EVT_WDF_DEVICE_FILE_CREATE G116FileCreate;
static volatile LONG G116Attempts,G116Ready,G116Fault,G116Maps;
static volatile LONG64 G116Sequence;
static G116_CAPTURE*G116Frozen;
#include "guard-and-status.inc"

static int NoManagedRam(void)
{
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>MAXULONGLONG-start)break;
  for(ULONG j=0;j<G116_PAGES;j++)if(start<G116Plan[j].Page+4096&&G116Plan[j].Page<start+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static ULONG Word(G116_CAPTURE*out,PVOID map,ULONG offset)
{
 KeMemoryBarrier();ULONG v=*(volatile const ULONG*)((const UCHAR*)map+offset);KeMemoryBarrier();out->ReadBytes+=4;return v;
}
static void Store(G116_CAPTURE*out,ULONG index,ULONG pass,PVOID map)
{
 G116_REGION*r=out->Regions+index;ULONG*dst=(ULONG*)(out->Payload+r->Offset+pass*r->Bytes);
 for(ULONG j=0;j<G116Plan[index].Count;j++)dst[j]=Word(out,map,G116Plan[index].Off[j]);
 r->Status|=1u<<pass;
 if(pass)out->CompleteMask|=1u<<index;
}
static int Gates(G116_CAPTURE*out,PVOID*maps)
{
 unsigned a[3],b[2];
 for(ULONG i=0;i<3;i++)a[i]=Word(out,maps[0],G116Plan[0].Off[i]);
 for(ULONG i=0;i<2;i++)b[i]=Word(out,maps[1],G116Plan[1].Off[i]);
 return G116Gate(a,b);
}
static PVOID Map(G116_CAPTURE*out,ULONG index)
{
 PHYSICAL_ADDRESS a;a.QuadPart=(LONGLONG)G116Plan[index].Page;out->MapCalls++;InterlockedIncrement(&G116Maps);
 return MmMapIoSpaceEx(a,4096,PAGE_READONLY|PAGE_NOCACHE);
}
static void Capture(G116_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 PVOID clocks[4]={0};LARGE_INTEGER delay;ULONG offset=0;
 Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!FullWindows()){out->Code=1001;goto done;}
 if(!NoManagedRam()){out->Code=1002;goto done;}
 for(ULONG i=0;i<G116_PAGES;i++){
  ULONG bytes=G116Plan[i].Count*4;if(i>=20||offset+2*bytes>G116_PAYLOAD){out->Code=1003;goto done;}
  out->Regions[i]=(G116_REGION){G116Plan[i].Page,bytes,offset,0,0,i,0};offset+=2*bytes;out->RegionCount++;
 }
 out->PayloadBytes=offset;
 for(ULONG i=0;i<4;i++){
  if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
  clocks[i]=Map(out,i);if(!clocks[i]){out->Code=1005;goto done;}
 }
 for(ULONG pass=0;pass<2;pass++){
  for(ULONG i=0;i<4;i++)Store(out,i,pass,clocks[i]);
  if(!Gates(out,clocks)){out->Code=2001;goto done;}
  for(ULONG i=4;i<G116_PAGES;i++){
   if(WdfRequestIsCanceled(request)){out->Code=1004;goto done;}
   if(!Gates(out,clocks)){out->Code=2002;goto done;}
   PVOID map=Map(out,i);if(!map){out->Code=1005;goto done;}
   ULONG values[12]={0};
   for(ULONG j=0;j<G116Plan[i].Count;j++){
    if(WdfRequestIsCanceled(request)){out->Code=1004;break;}
    if(!Gates(out,clocks)){out->Code=2002;break;}
    values[j]=Word(out,map,G116Plan[i].Off[j]);
    if(!Gates(out,clocks)){out->Code=2002;break;}
   }
   MmUnmapIoSpace(map,4096);
   if(out->Code)goto done;
   G116_REGION*r=out->Regions+i;
   RtlCopyMemory(out->Payload+r->Offset+pass*r->Bytes,values,r->Bytes);
   r->Status|=1u<<pass;if(pass)out->CompleteMask|=1u<<i;
   if(i==4){ULONG v=*(ULONG*)(out->Payload+out->Regions[i].Offset+pass*4);if((v&0xffff0000u)!=0x90000000u){out->Code=2003;goto done;}}
  }
  if(!Gates(out,clocks)){out->Code=2004;goto done;}
  if(!pass){delay.QuadPart=-500000;KeDelayExecutionThread(KernelMode,FALSE,&delay);}
 }
 done:for(ULONG i=0;i<4;i++)if(clocks[i])MmUnmapIoSpace(clocks[i],4096);
 out->End=KeQueryInterruptTime();if(out->Code)InterlockedExchange(&G116Fault,1);
 InterlockedExchange(&G116Ready,1);Status(&out->Status);
}
VOID G116Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G116_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G116_IOCTL_STATUS&&code!=G116_IOCTL_READ&&code!=G116_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G116_ABI||in.Magic!=G116_MAGIC||in.Reserved||in.Count||(code==G116_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G116_IOCTL_STATUS?sizeof(G116_STATUS):sizeof(G116_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G116_IOCTL_STATUS)Status(output);
 else if(code==G116_IOCTL_RESULT){if(!InterlockedCompareExchange(&G116Ready,0,0)||G116Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G116Frozen,sizeof(*G116Frozen));}
 else{if(InterlockedCompareExchange(&G116Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G116Frozen,sizeof(*G116Frozen));Capture(G116Frozen,request,in.Nonce);RtlCopyMemory(output,G116Frozen,sizeof(*G116Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
