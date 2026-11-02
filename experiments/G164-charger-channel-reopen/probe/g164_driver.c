/* SPDX-License-Identifier: MIT
 * Fixed finite GLINK charger-router query batch in this WinPE context.
 * Only the PMIC router channel and fixed read-only queries; no PAS/reset/setter.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g164_binding.h"
#include "g164_core.h"
#include "g164_slots.h"
#include "g164_protocol.h"
#include "smem-select.h"
typedef SIZE_T UINTN;
#define STATIC static
#define CONST const
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#include "OpenSha256.h"
#undef CopyMem
#undef ZeroMem
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G164Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G164Control;
EVT_WDF_DEVICE_FILE_CREATE G164FileCreate;
static volatile LONG G164Attempts,G164Ready,G164Fault,G164Maps;
static volatile LONG64 G164Sequence;
static G164_CAPTURE*G164Frozen;
#include "guard-and-status.inc"

static int ReservedRam(void)
{
 const ULONGLONG bases[]={0x400000ULL,0x81a00000ULL,0x81d00000ULL};
 const ULONGLONG lengths[]={0x100000ULL,0x300000ULL,0x200000ULL};
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>MAXULONGLONG-start)break;
  for(ULONG j=0;j<3;j++)if(start<bases[j]+lengths[j]&&bases[j]<start+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static PVOID Map(G164_CAPTURE*out,ULONGLONG physical,SIZE_T bytes,ULONG protection)
{
 PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)physical;
 out->MapCalls++;InterlockedIncrement(&G164Maps);
 return MmMapIoSpaceEx(at,bytes,protection);
}
typedef struct {
 const G164_STATE*State;volatile ULONG*Descriptor;
 volatile UCHAR*Tx;volatile UCHAR*Rx;volatile ULONG*Doorbell;
}G164_NATIVE_IO;
static void Barrier(void*context){UNREFERENCED_PARAMETER(context);KeMemoryBarrier();}
static int ReadDescriptor(void*context,uint32_t words[8])
{
 G164_NATIVE_IO*io=context;KeMemoryBarrier();
 for(ULONG i=0;i<8;i++)words[i]=io->Descriptor[i];KeMemoryBarrier();return 1;
}
static int ReadRx(void*context,uint32_t at,uint8_t*frame,uint32_t n)
{
 G164_NATIVE_IO*io=context;if(at>=G164_FIFO_BYTES||(at&7)||!n||n>G164_FRAME_BYTES)return 0;
 KeMemoryBarrier();for(ULONG i=0;i<n;i++)frame[i]=io->Rx[(at+i)&G164_FIFO_MASK];KeMemoryBarrier();return 1;
}
static int WriteTx(void*context,uint32_t at,const uint8_t*frame,uint32_t n)
{
 G164_NATIVE_IO*io=context;if(at>=G164_FIFO_BYTES||(at&7)||!G164ValidateTx(io->State,frame,n))return 0;
 for(ULONG i=0;i<n;i++)io->Tx[(at+i)&G164_FIFO_MASK]=frame[i];KeMemoryBarrier();return 1;
}
static int PublishHostWord(void*context,uint32_t word,uint32_t value)
{
 G164_NATIVE_IO*io=context;if((word!=1&&word!=2)||value>=G164_FIFO_BYTES||(value&7))return 0;
 KeMemoryBarrier();io->Descriptor[word]=value;KeMemoryBarrier();return io->Descriptor[word]==value;
}
static int Kick(void*context)
{
 G164_NATIVE_IO*io=context;
 /* Original Glink4e58 -> IPCC protocol+28 ->1f14/1e50/2040, replayed G157:
  * physical40800c, target CID3, signal0, one32-bit write; no read/modify/write. */
 KeMemoryBarrier();*io->Doorbell=0x30000;KeMemoryBarrier();return 1;
}
static void Capture(G164_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 static const UCHAR expected[32]={0xf0,0x85,0x4f,0x17,0x17,0x13,0x51,0xb6,0x02,0x54,0x53,0x89,0x41,0x04,0x4e,0x68,0xca,0xe2,0x83,0xf1,0xf6,0xc9,0x24,0x3f,0xaa,0x14,0xb7,0x1b,0xad,0xbc,0x2e,0x29};
 PVOID fdt=NULL,toc=NULL,part=NULL,irq=NULL;G135_PART parts[2];uint32_t count=0;
 G164_NATIVE_IO native={0};G164_IO io={ReadDescriptor,ReadRx,WriteTx,PublishHostWord,Barrier,Kick,&native};
 G158_SLOTS second;LARGE_INTEGER delay;int result=G164_WAIT;
 Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!WinPE()){out->Code=1001;goto done;}
 if(!ReservedRam()){out->Code=1002;goto done;}
 fdt=Map(out,0x81a04000,0x10000,PAGE_READONLY);
 if(!fdt){out->Code=1003;goto done;}
 OpenShaAll(fdt,60399,out->FdtDigest);
 if(RtlCompareMemory(out->FdtDigest,expected,32)!=32){out->Code=1004;goto done;}
 out->FdtMatch=1;MmUnmapIoSpace(fdt,0x10000);fdt=NULL;
 toc=Map(out,0x81eff000,0x1000,PAGE_READONLY|PAGE_NOCACHE);
 if(!toc){out->Code=1005;goto done;}
 if(G135Select(toc,4096,parts,&count)||count!=2){out->Code=1006;goto done;}
 ULONG selected=2;for(ULONG i=0;i<count;i++)if(parts[i].Host0==0&&parts[i].Host1==2)selected=i;
 if(selected==2||parts[selected].Offset!=0x19f000||parts[selected].Bytes!=0x60000){out->Code=1006;goto done;}
 out->TocMatch=1;MmUnmapIoSpace(toc,0x1000);toc=NULL;
 part=Map(out,0x81e9f000,0x60000,PAGE_READWRITE|PAGE_NOCACHE);
 if(!part){out->Code=1007;goto done;}
 if(!G135PartHeader(part,parts+selected)||!G158FindSlots(part,0x60000,&out->Slots)){out->Code=1008;goto done;}
 KeMemoryBarrier();
 if(!G135PartHeader(part,parts+selected)||!G158FindSlots(part,0x60000,&second)||RtlCompareMemory(&second,&out->Slots,sizeof(second))!=sizeof(second)){out->Code=1008;goto done;}
 out->SlotsMatch=1;
 native.State=&out->State;
 native.Descriptor=(volatile ULONG*)((UCHAR*)part+out->Slots.Descriptor);
 native.Tx=(volatile UCHAR*)part+out->Slots.Tx;native.Rx=(volatile UCHAR*)part+out->Slots.Rx;
 ReadDescriptor(&native,out->InitialDescriptor);
 irq=Map(out,0x408000,0x1000,PAGE_READWRITE|PAGE_NOCACHE);
 if(!irq){out->Code=1009;goto done;}
 native.Doorbell=(volatile ULONG*)((UCHAR*)irq+0xc);
 delay.QuadPart=-50000; /*5ms; soft8s close, hard10s,2000 steps.*/
 for(ULONG step=0;step<2000;step++){
  if(!out->State.Started&&WdfRequestIsCanceled(request)){out->Cancelled=1;out->Code=1010;break;}
  ULONGLONG elapsed=KeQueryInterruptTime()-out->Begin;
  if(elapsed>=100000000){out->TimedOut=1;out->Code=3001;break;}
  if(elapsed>=80000000&&!out->State.Closing){
   out->TimedOut=1;
   if(!out->State.OpenSent){out->Code=3001;break;}
   out->State.Fault=G164_F_TIMEOUT;out->State.Closing=1;
  }
  result=G164Step(&out->State,&io);
  if(result==G164_COMPLETE)break;
  if(result==G164_REFUSED){out->Code=2000+out->State.Fault;break;}
  if(!NT_SUCCESS(KeDelayExecutionThread(KernelMode,FALSE,&delay))){out->Code=1011;break;}
 }
 if(result==G164_WAIT&&!out->Code){out->Code=3001;out->TimedOut=1;}
 done:
 if(part&&out->SlotsMatch){
  ReadDescriptor(&native,out->FinalDescriptor);
  KeMemoryBarrier();for(ULONG i=0;i<G164_FIFO_BYTES;i++){out->Tx[i]=native.Tx[i];out->Rx[i]=native.Rx[i];}KeMemoryBarrier();
 }
 if(irq)MmUnmapIoSpace(irq,0x1000);
 if(part)MmUnmapIoSpace(part,0x60000);
 if(toc)MmUnmapIoSpace(toc,0x1000);
 if(fdt)MmUnmapIoSpace(fdt,0x10000);
 out->End=KeQueryInterruptTime();if(out->Code)InterlockedExchange(&G164Fault,1);
 InterlockedExchange(&G164Ready,1);Status(&out->Status);
}
VOID G164Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G164_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G164_IOCTL_STATUS&&code!=G164_IOCTL_READ&&code!=G164_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G164_ABI||in.Magic!=G164_MAGIC||in.Reserved||in.Count||(code==G164_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G164_IOCTL_STATUS?sizeof(G164_STATUS):sizeof(G164_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G164_IOCTL_STATUS)Status(output);
 else if(code==G164_IOCTL_RESULT){if(!InterlockedCompareExchange(&G164Ready,0,0)||G164Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G164Frozen,sizeof(*G164Frozen));}
 else{if(InterlockedCompareExchange(&G164Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G164Frozen,sizeof(*G164Frozen));Capture(G164Frozen,request,in.Nonce);RtlCopyMemory(output,G164Frozen,sizeof(*G164Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
#include "lifecycle.inc"
