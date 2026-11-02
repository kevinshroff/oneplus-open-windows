/* SPDX-License-Identifier: MIT
 * Maintained, GET-only GLINK owner for the admitted G155 WinPE target.
 * Control device and passive nonperiodic timer share WDF device serialization.
 * Client handles and USB have no influence on the transport's lifetime.
 * This bring-up adapter does not claim a production PnP/power/resource lease.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "binding.h"
#include "link_core.h"
#include "slots.h"
#include "protocol.h"
#include "abi-checks.h"
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
EVT_WDF_DRIVER_UNLOAD ClnUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ClnControl;
EVT_WDF_DEVICE_FILE_CREATE ClnFileCreate;
EVT_WDF_TIMER ClnTimer;
typedef struct {
 CLN_SNAPSHOT_DATA Data;
 PVOID Part,Irq;
 volatile ULONG *Descriptor,*Doorbell;volatile UCHAR *Tx,*Rx;
}CLN_OWNER;
static CLN_OWNER *Owner;
static WDFTIMER Timer;
static WDFDEVICE Device;
#include "guard.inc"
#include "reserved.inc"
static uint64_t Now(void){return KeQueryInterruptTime()/10;}
static void Identity(CLN_SNAPSHOT_DATA*s)
{
 UCHAR dsdt[sizeof(ClnExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version={0};
 s->Size=sizeof(*s);s->Version=CLN_ABI;s->Magic=CLN_MAGIC;
 s->NowUs=Now();s->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);s->Irql=KeGetCurrentIrql();
 s->FirmwareMatch=s->KernelBuild=s->WinPE=0;
 if(s->Irql!=PASSIVE_LEVEL){s->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))s->KernelBuild=version.dwBuildNumber;
 s->FirmwareStatus=(ULONG)AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&bytes);s->FirmwareBytes=bytes;
 if(NT_SUCCESS((NTSTATUS)s->FirmwareStatus)&&bytes==sizeof(dsdt)&&RtlCompareMemory(dsdt,ClnExpectedDsdt,sizeof(dsdt))==sizeof(dsdt))s->FirmwareMatch=1;
 s->WinPE=(uint32_t)WinPE();
}
static void Unmap(void)
{
 /* Write-free even on forced unload/OS shutdown. A manager may deliberately
  * unload only after SafeToUnload; it must not discard an uncertain session. */
 if(Owner->Irq){MmUnmapIoSpace(Owner->Irq,0x1000);Owner->Irq=NULL;}
 if(Owner->Part){MmUnmapIoSpace(Owner->Part,0x60000);Owner->Part=NULL;}
 Owner->Descriptor=Owner->Doorbell=NULL;Owner->Tx=Owner->Rx=NULL;Owner->Data.MapsLive=0;
}
static PVOID Map(ULONGLONG at,SIZE_T bytes,ULONG protection)
{
 PHYSICAL_ADDRESS p;p.QuadPart=(LONGLONG)at;Owner->Data.MapCalls++;
 return MmMapIoSpaceEx(p,bytes,protection);
}
static void Barrier(void*c){UNREFERENCED_PARAMETER(c);KeMemoryBarrier();}
static int Descriptor(void*c,uint32_t d[8])
{
 CLN_OWNER*o=c;if(!o->Descriptor||o->Data.Stopped)return 0;
 KeMemoryBarrier();for(ULONG i=0;i<8;i++)d[i]=o->Descriptor[i];KeMemoryBarrier();return 1;
}
static int Rx(void*c,uint32_t at,uint8_t*b,uint32_t n)
{
 CLN_OWNER*o=c;if(!o->Rx||o->Data.Stopped||at>=CL_FIFO_BYTES||(at&7)||!n||n>CL_FRAME_BYTES)return 0;
 KeMemoryBarrier();for(ULONG i=0;i<n;i++)b[i]=o->Rx[(at+i)&CL_FIFO_MASK];KeMemoryBarrier();return 1;
}
static int Tx(void*c,uint32_t at,const uint8_t*b,uint32_t n)
{
 CLN_OWNER*o=c;if(!o->Tx||o->Data.Stopped||at>=CL_FIFO_BYTES||(at&7)||!ClTxAllowed(&o->Data.State,b,n))return 0;
 for(ULONG i=0;i<n;i++)o->Tx[(at+i)&CL_FIFO_MASK]=b[i];KeMemoryBarrier();return 1;
}
static int Publish(void*c,uint32_t word,uint32_t value)
{
 CLN_OWNER*o=c;if(!o->Descriptor||o->Data.Stopped||(word!=1&&word!=2)||value>=CL_FIFO_BYTES||(value&7))return 0;
 KeMemoryBarrier();o->Descriptor[word]=value;KeMemoryBarrier();return o->Descriptor[word]==value;
}
static int Kick(void*c)
{
 CLN_OWNER*o=c;if(!o->Doorbell||o->Data.Stopped)return 0;
 /* Original firmware Glink4e58 -> IPCC+28 ->1f14/1e50/2040, G157 replay:
  * one32-bit write at40800c, CID3/signal0. No read/modify/write. */
 KeMemoryBarrier();*o->Doorbell=0x30000;KeMemoryBarrier();return 1;
}
static int Admit(void)
{
 static const UCHAR expected[32]={0xf0,0x85,0x4f,0x17,0x17,0x13,0x51,0xb6,0x02,0x54,0x53,0x89,0x41,0x04,0x4e,0x68,0xca,0xe2,0x83,0xf1,0xf6,0xc9,0x24,0x3f,0xaa,0x14,0xb7,0x1b,0xad,0xbc,0x2e,0x29};
 CLN_SNAPSHOT_DATA *s=&Owner->Data;PVOID fdt=NULL,toc=NULL;G135_PART parts[2];uint32_t count=0;G158_SLOTS second;
 Identity(s);s->Attempted=1;s->SafeToUnload=0;
 if(!s->FirmwareMatch||s->KernelBuild!=26100||s->Processors!=8||s->Irql!=PASSIVE_LEVEL||!s->WinPE){s->AdmissionCode=1001;goto refused;}
 if(!ReservedRam()){s->AdmissionCode=1002;goto refused;}
 fdt=Map(0x81a04000,0x10000,PAGE_READONLY);if(!fdt){s->AdmissionCode=1003;goto refused;}
 OpenShaAll(fdt,60399,s->FdtDigest);if(RtlCompareMemory(s->FdtDigest,expected,32)!=32){s->AdmissionCode=1004;goto refused;}
 MmUnmapIoSpace(fdt,0x10000);fdt=NULL;
 toc=Map(0x81eff000,0x1000,PAGE_READONLY|PAGE_NOCACHE);if(!toc){s->AdmissionCode=1005;goto refused;}
 if(G135Select(toc,4096,parts,&count)||count!=2){s->AdmissionCode=1006;goto refused;}
 ULONG selected=2;for(ULONG i=0;i<count;i++)if(parts[i].Host0==0&&parts[i].Host1==2)selected=i;
 if(selected==2||parts[selected].Offset!=0x19f000||parts[selected].Bytes!=0x60000){s->AdmissionCode=1006;goto refused;}
 MmUnmapIoSpace(toc,0x1000);toc=NULL;
 Owner->Part=Map(0x81e9f000,0x60000,PAGE_READWRITE|PAGE_NOCACHE);if(!Owner->Part){s->AdmissionCode=1007;goto refused;}
 if(!G135PartHeader(Owner->Part,parts+selected)||!G158FindSlots(Owner->Part,0x60000,&s->Slots)){s->AdmissionCode=1008;goto refused;}
 KeMemoryBarrier();
 if(!G135PartHeader(Owner->Part,parts+selected)||!G158FindSlots(Owner->Part,0x60000,&second)||RtlCompareMemory(&second,&s->Slots,sizeof(second))!=sizeof(second)){s->AdmissionCode=1008;goto refused;}
 Owner->Descriptor=(volatile ULONG*)((UCHAR*)Owner->Part+s->Slots.Descriptor);
 Owner->Tx=(volatile UCHAR*)Owner->Part+s->Slots.Tx;Owner->Rx=(volatile UCHAR*)Owner->Part+s->Slots.Rx;
 if(!Descriptor(Owner,s->InitialDescriptor)){s->AdmissionCode=1008;goto refused;}
 for(ULONG i=0;i<8;i++)if(s->InitialDescriptor[i]!=(i==3?8u:0u)){s->AdmissionCode=1010;goto refused;}
 Owner->Irq=Map(0x408000,0x1000,PAGE_READWRITE|PAGE_NOCACHE);if(!Owner->Irq){s->AdmissionCode=1009;goto refused;}
 Owner->Doorbell=(volatile ULONG*)((UCHAR*)Owner->Irq+0xc);s->MapsLive=2;s->Running=1;return 1;
 refused:
 if(toc)MmUnmapIoSpace(toc,0x1000);if(fdt)MmUnmapIoSpace(fdt,0x10000);Unmap();s->SafeToUnload=1;s->Stopped=1;return 0;
}
static void Pump(void)
{
 CLN_SNAPSHOT_DATA*s=&Owner->Data;
 CL_IO io={Descriptor,Rx,Tx,Publish,Barrier,Kick,Owner};
 if(!s->Running||s->Stopped)return;
 for(ULONG n=0;n<16;n++){
  int r=ClPoll(&s->State,&io,Now());
  RtlCopyMemory(s->FinalDescriptor,s->State.LastDescriptor,sizeof(s->FinalDescriptor));
  if(r==CL_POLL_CLOSED){s->Running=0;s->Stopped=1;s->SafeToUnload=1;Unmap();return;}
  if(r==CL_POLL_FAULT){
   s->Running=0;s->Stopped=1;s->NativeFault=1;
   if(!s->State.TxWriteAttempts&&!s->State.CounterWriteAttempts&&!s->State.KickAttempts){s->SafeToUnload=1;Unmap();}
   return; /* mappings/context retained if any write was attempted */
  }
  if(r==CL_POLL_IDLE)break;
 }
 if(s->Running&&!s->Stopped)WdfTimerStart(Timer,WDF_REL_TIMEOUT_IN_MS(s->State.BatchActive||s->State.Phase!=CL_READY?5:25));
}
VOID ClnTimer(WDFTIMER timer)
{
 UNREFERENCED_PARAMETER(timer);if(!Owner)return;
 if(Owner->Data.TimerCalls==UINT64_MAX){Owner->Data.NativeFault=1;Owner->Data.Stopped=1;Owner->Data.Running=0;return;}
 Owner->Data.TimerCalls++;Pump();
}
static int Command(ULONG action,const CLN_REQUEST*in)
{
 CLN_SNAPSHOT_DATA*s=&Owner->Data;uint64_t now=Now();int rc;
 if(in->Cookie!=s->Cookie||!in->Cookie||!in->CommandId)return 0;
 /* A repeated request returns the present snapshot, never another wire action.
  * Strictly consecutive IDs also reject uncertain/out-of-order client work. */
 if(in->CommandId==s->LastCommandId)return action==s->LastAction;
 if(s->LastCommandId==UINT64_MAX||in->CommandId!=s->LastCommandId+1)return 0;
 if(action==CLN_START){if(s->Attempted)return 0;}
 else if(!s->Attempted||s->Stopped||!s->Running)return 0;
 s->LastCommandId=in->CommandId;s->LastAction=action;s->LastResult=0;
 if(action==CLN_START){if(Admit()){s->LastResult=1;Pump();}return 1;}
 rc=action==CLN_SAMPLE?ClRequestBatch(&s->State,now):
    action==CLN_BOARD_FV?ClRequestBoardFv(&s->State,now):ClRequestClose(&s->State,now);
 s->LastResult=rc>0?1u:rc==0?2u:3u;
 if(rc>0)Pump();return 1;
}
VOID ClnControl(WDFQUEUE queue,WDFREQUEST request,size_t outBytes,size_t inBytes,ULONG code)
{
 CLN_REQUEST in,*input;CLN_SNAPSHOT_DATA*output;NTSTATUS status;ULONG_PTR info=0;UNREFERENCED_PARAMETER(queue);
 if(code!=CLN_STATUS&&code!=CLN_SNAPSHOT&&code!=CLN_START&&code!=CLN_SAMPLE&&code!=CLN_CLOSE&&code!=CLN_BOARD_FV){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=CLN_ABI||in.Magic!=CLN_MAGIC||in.Flags||in.Reserved){status=STATUS_INVALID_PARAMETER;goto done;}
 if(outBytes!=sizeof(*output)){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,sizeof(*output),(PVOID*)&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==CLN_STATUS||code==CLN_SNAPSHOT){if(in.Cookie||in.CommandId){status=STATUS_INVALID_PARAMETER;goto done;}}
 else if(!Command(code,&in)){status=STATUS_INVALID_DEVICE_STATE;goto done;}
 Identity(&Owner->Data);RtlCopyMemory(output,&Owner->Data,sizeof(*output));info=sizeof(*output);status=STATUS_SUCCESS;
 done:WdfRequestCompleteWithInformation(request,status,info);
}
VOID ClnFileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);
 WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID ClnUnload(WDFDRIVER driver)
{
 UNREFERENCED_PARAMETER(driver);
 /* Driver callback is outside the automatically serialized device callbacks.
  * Stop(TRUE) drains a running callback before context/maps can be freed. */
 /* Prevent a running callback from rearming itself before waiting for it.
  * Never wait with the device callback lock held. */
 if(Device){WdfObjectAcquireLock(Device);if(Owner){Owner->Data.Stopped=1;Owner->Data.Running=0;}WdfObjectReleaseLock(Device);}
 if(Timer){WdfTimerStop(Timer,TRUE);Timer=NULL;}
 if(Owner){Owner->Data.Stopped=1;Owner->Data.Running=0;Unmap();ExFreePoolWithTag(Owner,'56CO');Owner=NULL;}
 Device=NULL;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;
 WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;WDF_TIMER_CONFIG timer;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG169");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG169");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=ClnUnload;
 status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 Owner=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*Owner),'56CO');if(!Owner)return STATUS_INSUFFICIENT_RESOURCES;
 ClInitialize(&Owner->Data.State);Owner->Data.Cookie=KeQueryInterruptTime()^((uint64_t)KeQueryPerformanceCounter(NULL).QuadPart<<1);if(!Owner->Data.Cookie)Owner->Data.Cookie=1;
 Owner->Data.SafeToUnload=1;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);WdfDeviceInitSetExclusive(init,TRUE);
 WDF_FILEOBJECT_CONFIG_INIT(&file,ClnFileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 Device=device;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=ClnControl;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WDF_TIMER_CONFIG_INIT(&timer,ClnTimer);timer.AutomaticSerialization=TRUE;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ParentObject=device;attr.ExecutionLevel=WdfExecutionLevelPassive;
 status=WdfTimerCreate(&timer,&attr,&Timer);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status))ClnUnload(driver);return status;
}
