/* SPDX-License-Identifier: MIT
 * G99 fixed READ protocol, now served by the same native module as touch.
 * STATUS/RESULT do not touch MMIO; SAMPLE shares the mandatory bus gate.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g98_binding.h"
#define G99ExpectedDsdt G98ExpectedDsdt
#include "g99_core.h"
#include "g99_protocol.h"
#include "g100_bus.h"
#include "g100_keys.h"
#include "g100_protocol.h"
static int FullWindows(void)
{
 UNICODE_STRING name;OBJECT_ATTRIBUTES attributes;HANDLE key;NTSTATUS status;ULONG bytes=0;
 union {KEY_VALUE_PARTIAL_INFORMATION Info;UCHAR Storage[128];}value;
 static const WCHAR expected[]=L"C:\\Windows";
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\MiniNT");InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(NT_SUCCESS(status)){ZwClose(key);return 0;}if(status!=STATUS_OBJECT_NAME_NOT_FOUND&&status!=STATUS_OBJECT_PATH_NOT_FOUND)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(!NT_SUCCESS(status))return 0;
 RtlInitUnicodeString(&name,L"SystemRoot");status=ZwQueryValueKey(key,&name,KeyValuePartialInformation,&value,sizeof(value),&bytes);ZwClose(key);
 return NT_SUCCESS(status)&&bytes<=sizeof(value)&&value.Info.Type==REG_SZ&&(value.Info.DataLength==sizeof(expected)||value.Info.DataLength==sizeof(expected)-sizeof(WCHAR))&&bytes>=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)+value.Info.DataLength&&RtlCompareMemory(value.Info.Data,expected,value.Info.DataLength)==value.Info.DataLength;
}
static void Status(G100_KEYS*k,G99_STATUS*s)
{
 UCHAR dsdt[sizeof(G99ExpectedDsdt)];ULONG bytes=0;NTSTATUS status;RTL_OSVERSIONINFOW version;LARGE_INTEGER freq;
 RtlZeroMemory(s,sizeof(*s));s->Size=sizeof(*s);s->Version=G99_ABI;s->Magic=G99_MAGIC;s->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);s->Irql=KeGetCurrentIrql();s->MapCalls=(ULONG)InterlockedCompareExchange(&k->Maps,0,0);s->Attempts=(ULONG)InterlockedCompareExchange(&k->Attempts,0,0);s->Ready=(ULONG)InterlockedCompareExchange(&k->Ready,0,0);s->Fault=(ULONG)InterlockedCompareExchange(&k->Fault,0,0);s->InterruptTime=KeQueryInterruptTime();s->Sequence=(ULONGLONG)InterlockedIncrement64(&k->Sequence);KeQueryPerformanceCounter(&freq);s->Frequency=(ULONGLONG)freq.QuadPart;
 if(s->Irql!=PASSIVE_LEVEL){s->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))s->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&bytes);s->FirmwareStatus=(ULONG)status;s->FirmwareBytes=bytes;if(NT_SUCCESS(status)&&bytes==sizeof(dsdt)&&RtlCompareMemory(dsdt,G99ExpectedDsdt,sizeof(dsdt))==sizeof(dsdt))s->FirmwareMatch=1;
}
static const ULONG Pages[5]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc444000};
typedef struct {PVOID Maps[5];WDFREQUEST Request;G100_KEYS*Keys;ULONG GateHeld;ULONG Reads,Writes,Guard;ULONGLONG Frequency;}G99_CONTEXT;
static PULONG Address(G99_CONTEXT*c,ULONG at,int write,ULONG value)
{
 if((at&3)||(write?!G99WriteAllowed(at,value):!G99ReadAllowed(at)))return NULL;
 for(ULONG i=0;i<5;i++)if(c->Maps[i]&&at>=Pages[i]&&at-Pages[i]<=0xffc){if(write&&i<3)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-Pages[i]);}return NULL;
}
static int NativeRead(void*x,uint32_t at,uint32_t*v)
{
 G99_CONTEXT*c=x;PULONG p;if(c->Reads>=80000||(at>=0xc440000&&at<0xc446000&&!c->GateHeld))return 0;p=Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int NativeWrite(void*x,uint32_t at,uint32_t value)
{
 G99_CONTEXT*c=x;PULONG p;uint32_t map,owner,status,previous;unsigned i;
 if(!c->GateHeld||c->Writes>=G99_MAX_COMMANDS||!G99WriteAllowed(at,value)){c->Guard=1;return 0;}
 if(WdfRequestIsCanceled(c->Request)||!c->Keys->Available(c->Keys->Owner)){c->Guard=4;return 0;}
 for(i=0;i<4;i++)if(at==G99Base(i))break;if(i==4){c->Guard=1;return 0;}
 if(!NativeRead(c,0xc402000+G99Targets[i].Apid*4,&map)||!NativeRead(c,0xc42d000+G99Targets[i].Apid*4,&owner)||map!=G99Targets[i].Map||owner!=G99Targets[i].Owner){c->Guard=2;return 0;}
 if(!NativeRead(c,at+8,&status)||!NativeRead(c,at,&previous)||(!(status&1)&&previous)){c->Guard=3;return 0;}
 p=Address(c,at,1,value);if(!p){c->Guard=1;return 0;}c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void WaitUs(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(1);}
static void WaitInterval(void*x){LARGE_INTEGER wait;UNREFERENCED_PARAMETER(x);wait.QuadPart=-200000;KeDelayExecutionThread(KernelMode,FALSE,&wait);}
static int Available(void*x){G99_CONTEXT*c=x;return !WdfRequestIsCanceled(c->Request)&&c->Keys->Available(c->Keys->Owner);}
static int Acquire(void*x){G99_CONTEXT*c=x;return G100BusAcquire(&c->GateHeld,Available,c);}
static void Release(void*x,int uncertain){G99_CONTEXT*c=x;G100BusRelease(&c->GateHeld,uncertain);}
static uint64_t NowUs(void*x){G99_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG u=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return u/c->Frequency*1000000+(u%c->Frequency)*1000000/c->Frequency;}
static void Capture(G100_KEYS*k,G99_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce,ULONG count)
{
 G99_CONTEXT c;G99_IO io;Status(k,&out->Status);out->Nonce=nonce;out->Requested=count;out->Result.Size=sizeof(out->Result);RtlZeroMemory(&c,sizeof(c));c.Request=request;c.Keys=k;c.Frequency=out->Status.Frequency;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!c.Frequency||c.Frequency>1000000000ULL||!FullWindows()||!k->Available(k->Owner)){out->Result.Code=1004;goto done;}
 for(ULONG i=0;i<5;i++){PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];InterlockedIncrement(&k->Maps);c.Maps[i]=MmMapIoSpaceEx(a,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);if(!c.Maps[i]){out->Result.Code=1005;goto done;}}
 io.Context=&c;io.Read=NativeRead;io.Write=NativeWrite;io.WaitUs=WaitUs;io.WaitInterval=WaitInterval;io.Available=Available;io.NowUs=NowUs;io.Acquire=Acquire;io.Release=Release;G99Sample(&io,count,&out->Result);
 done:for(ULONG i=5;i;i--)if(c.Maps[i-1])MmUnmapIoSpace(c.Maps[i-1],0x1000);
 out->NativeReads=c.Reads;out->NativeWrites=c.Writes;out->NativeGuard=c.Guard;if(out->Result.Code)InterlockedExchange(&k->Fault,1);
 InterlockedExchange(&k->Ready,1);Status(k,&out->Status);
}
int G100KeysTryControl(G100_KEYS*k,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G99_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 if(code!=G99_IOCTL_STATUS&&code!=G99_IOCTL_SAMPLE&&code!=G99_IOCTL_RESULT&&code!=G100_IOCTL_BUS)return 0;
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G99_ABI||in.Magic!=G99_MAGIC||in.Reserved||((code==G99_IOCTL_STATUS||code==G100_IOCTL_BUS)?in.Nonce||in.Count:!in.Nonce)||(code==G99_IOCTL_RESULT&&in.Count)||(code==G99_IOCTL_SAMPLE&&(!in.Count||in.Count>G99_MAX_SAMPLES))){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G100_IOCTL_BUS?sizeof(G100_BUS_STATUS):code==G99_IOCTL_STATUS?sizeof(G99_STATUS):sizeof(G99_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G100_IOCTL_BUS)G100BusStatus(output);
 else if(code==G99_IOCTL_STATUS)Status(k,output);
 else if(code==G99_IOCTL_RESULT){if(!InterlockedCompareExchange(&k->Ready,0,0)||((G99_CAPTURE*)k->Frozen)->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,((G99_CAPTURE*)k->Frozen),sizeof(*((G99_CAPTURE*)k->Frozen)));}
 else{if(InterlockedCompareExchange(&k->Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(((G99_CAPTURE*)k->Frozen),sizeof(*((G99_CAPTURE*)k->Frozen)));Capture(k,((G99_CAPTURE*)k->Frozen),request,in.Nonce,in.Count);RtlCopyMemory(output,((G99_CAPTURE*)k->Frozen),sizeof(*((G99_CAPTURE*)k->Frozen)));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);return 1;
}

NTSTATUS G100KeysInitialize(G100_KEYS*k,void*owner,int(*available)(void*))
{
 RtlZeroMemory(k,sizeof(*k));k->Owner=owner;k->Available=available;
 k->Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(G99_CAPTURE),'00GO');
 return k->Frozen?STATUS_SUCCESS:STATUS_INSUFFICIENT_RESOURCES;
}
void G100KeysFree(G100_KEYS*k)
{
 if(k->Frozen){ExFreePoolWithTag(k->Frozen,'00GO');k->Frozen=NULL;}
}
