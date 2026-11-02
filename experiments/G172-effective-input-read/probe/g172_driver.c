/* SPDX-License-Identifier: MIT
 * Fixed one-shot charger observer. No touch-driver changes and no PMIC writes.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g172_binding.h"
#include "g172_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G172Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G172Control;
EVT_WDF_DEVICE_FILE_CREATE G172FileCreate;
static volatile LONG G172Attempts,G172Ready,G172Fault,G172Maps;
static volatile LONG64 G172Sequence;
static G172_CAPTURE*G172Frozen;
#include "guard-and-status.inc"
static const ULONG Pages[5]={0xc400000,0xc402000,0xc42d000,0xc443000,0xc445000};
typedef struct{PVOID Maps[5];WDFREQUEST Request;ULONG Own,Reads,Writes,Guard;ULONGLONG Frequency;}G111_CONTEXT;
static int NoManagedRam(void){
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){ULONGLONG a=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;if(!n){valid=1;break;}if(n>MAXULONGLONG-a)break;for(ULONG j=0;j<5;j++)if(a<(ULONGLONG)Pages[j]+4096&&Pages[j]<a+n)goto done;}
 done:ExFreePool(ranges);return valid;
}
static PULONG Address(G111_CONTEXT*c,uint32_t at,int write,uint32_t value){
 if((at&3)||(write?!G111WriteAllowed(at,value):!G111ReadAllowed(at)))return NULL;
 for(ULONG i=0;i<5;i++)if(c->Maps[i]&&at>=Pages[i]&&at-Pages[i]<=0xffc){if(write&&i<3)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-Pages[i]);}return NULL;
}
static int NativeRead(void*x,uint32_t at,uint32_t*v){
 G111_CONTEXT*c=x;PULONG p;if(!c->Own||c->Reads>=G111_READ_LIMIT)return 0;p=Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int Available(void*x){return !WdfRequestIsCanceled(((G111_CONTEXT*)x)->Request);}
static int NativeWrite(void*x,uint32_t at,uint32_t value){
 G111_CONTEXT*c=x;uint32_t map,owner,status,previous;unsigned i;PULONG p;
 if(!c->Own||!Available(c)||c->Writes>=G111_STEPS||!G111WriteAllowed(at,value)){c->Guard=1;return 0;}
 for(i=0;i<G111_TARGETS;i++)if(at==G111Base(i))break;if(i==G111_TARGETS){c->Guard=2;return 0;}
 if(!NativeRead(c,0xc402000+G111Targets[i].Apid*4,&map)||!NativeRead(c,0xc42d000+G111Targets[i].Apid*4,&owner)||map!=G111Targets[i].Map||owner!=G111Targets[i].Owner){c->Guard=3;return 0;}
 if(!NativeRead(c,at+8,&status)||!NativeRead(c,at,&previous)||(!(status&1)&&previous)){c->Guard=4;return 0;}
 p=Address(c,at,1,value);if(!p){c->Guard=5;return 0;}c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void WaitUs(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(1);}
static void WaitInterval(void*x){LARGE_INTEGER d;UNREFERENCED_PARAMETER(x);d.QuadPart=-200000;KeDelayExecutionThread(KernelMode,FALSE,&d);}
static uint64_t NowUs(void*x){G111_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG n=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return n/c->Frequency*1000000+(n%c->Frequency)*1000000/c->Frequency;}
static void Capture(G172_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce){
 G111_CONTEXT c;G111_IO io;RtlZeroMemory(&c,sizeof(c));Status(&out->Status);out->Nonce=nonce;out->Begin=KeQueryInterruptTime();c.Request=request;c.Frequency=out->Status.Frequency;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!WinPE()||!c.Frequency||c.Frequency>1000000000ULL){out->Result.Code=1001;goto done;}
 if(!NoManagedRam()){out->Result.Code=1002;goto done;}
 for(ULONG i=0;i<5;i++){PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];InterlockedIncrement(&G172Maps);c.Maps[i]=MmMapIoSpaceEx(a,4096,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);if(!c.Maps[i]){out->Result.Code=1005;goto done;}}
 c.Own=1;io=(G111_IO){&c,NativeRead,NativeWrite,WaitUs,WaitInterval,Available,NowUs};G111Observe(&io,&out->Result);
 done:c.Own=0;for(ULONG i=5;i;i--)if(c.Maps[i-1])MmUnmapIoSpace(c.Maps[i-1],4096);
 out->NativeReads=c.Reads;out->NativeWrites=c.Writes;out->NativeGuard=c.Guard;out->End=KeQueryInterruptTime();if(out->Result.Code)InterlockedExchange(&G172Fault,1);InterlockedExchange(&G172Ready,1);Status(&out->Status);
}
#include "control.inc"
#include "lifecycle.inc"
