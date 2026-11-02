/* Ongoing fixed sensor acquisition on exact PE26100 or normal Windows26300.
 * No charging setters,gauge configuration,GLINK or battery-class claims. */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "resources.h"
#include "binding.h"
#include "protocol.h"
#define OP184_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,OP184_FUNCTION,METHOD_BUFFERED,FILE_READ_ACCESS)
C_ASSERT(sizeof(OP184_REQUEST)==32);C_ASSERT(sizeof(OP184_STATUS_DATA)==176);
C_ASSERT(sizeof(S183_RESULT)==280840);C_ASSERT(sizeof(OP184_SNAPSHOT)==281104);
typedef struct {
 WDFWAITLOCK Lock;WDFTIMER Timer;WDFWORKITEM Work;WDFMEMORY WorkingMemory,LatestMemory;
 OP184_STATUS_DATA Data;S183_READING Reading;
 S183_RESULT *Working,*Latest;PVOID Maps[OP182_RESOURCE_COUNT];
 volatile LONG Cancel;ULONGLONG Frequency,NextDue100ns;
}OP184_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OP184_CONTEXT,Op184Context)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD Op184Add;
EVT_WDF_DEVICE_PREPARE_HARDWARE Op184Prepare;
EVT_WDF_DEVICE_RELEASE_HARDWARE Op184Release;
EVT_WDF_DEVICE_D0_ENTRY Op184D0Entry;
EVT_WDF_DEVICE_D0_EXIT Op184D0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Op184Control;
EVT_WDF_DEVICE_FILE_CREATE Op184FileCreate;
EVT_WDF_TIMER Op184Timer;
EVT_WDF_WORKITEM Op184Worker;
static const GUID Interface={0x8fa58184,0xfd04,0x4f21,{0x9f,0x08,0xa3,0x04,0xc1,0xbd,0x01,0x84}};
static void Op184Lock(OP184_CONTEXT*c){NTSTATUS s=WdfWaitLockAcquire(c->Lock,NULL);NT_ASSERT(NT_SUCCESS(s));UNREFERENCED_PARAMETER(s);}
static void Op184Unlock(OP184_CONTEXT*c){WdfWaitLockRelease(c->Lock);}
#include "identity.inc"
static int Identity(OP184_CONTEXT*c)
{
 UCHAR dsdt[sizeof(ClnExpectedDsdt)];ULONG got=0;RTL_OSVERSIONINFOW v={0};
 c->Data.KernelBuild=0;c->Data.Cpus=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);c->Data.Irql=KeGetCurrentIrql();v.dwOSVersionInfoSize=sizeof(v);
 if(NT_SUCCESS(RtlGetVersion(&v)))c->Data.KernelBuild=v.dwBuildNumber;
 NTSTATUS s=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&got);
 c->Data.FirmwareMatch=NT_SUCCESS(s)&&got==sizeof(dsdt)&&RtlCompareMemory(dsdt,ClnExpectedDsdt,sizeof(dsdt))==sizeof(dsdt);
 LARGE_INTEGER frequency;KeQueryPerformanceCounter(&frequency);c->Frequency=(ULONGLONG)frequency.QuadPart;
 return TargetOsMode(c->Data.KernelBuild)&&frequency.QuadPart>0&&c->Frequency<=1000000000ULL&&c->Data.Cpus==8&&c->Data.Irql==PASSIVE_LEVEL&&c->Data.FirmwareMatch;
}
static int NoManagedRam(void)
{
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;if(!ranges)return 0;
 for(unsigned i=0;i<512;i++){
  uint64_t a=(uint64_t)ranges[i].BaseAddress.QuadPart,n=(uint64_t)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>UINT64_MAX-a)break;
  for(unsigned j=0;j<OP182_RESOURCE_COUNT;j++)if(a<OP182Expected[j].Base+OP182Expected[j].Bytes&&OP182Expected[j].Base<a+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static void Unmap(OP184_CONTEXT*c)
{
 c->Data.Valid=0;c->Data.ProducerQualified=0;c->Data.D0Active=0;c->Data.Prepared=0;
 for(unsigned n=OP182_RESOURCE_COUNT;n;n--)if(c->Maps[n-1]){
  MmUnmapIoSpace(c->Maps[n-1],OP182Expected[n-1].Bytes);c->Maps[n-1]=NULL;c->Data.UnmapCalls++;c->Data.MapCount--;
 }
}
static uint32_t Convert(WDFCMRESLIST list,OP182_RESOURCE*out)
{
 if(WdfCmResourceListGetCount(list)!=OP182_RESOURCE_COUNT)return 10;
 for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR d=WdfCmResourceListGetDescriptor(list,i);
  if(!d||d->Type!=CmResourceTypeMemory)return 11;
  if(d->Flags&~CM_RESOURCE_MEMORY_READ_ONLY)return 12;
  out[i]=(OP182_RESOURCE){(uint64_t)d->u.Memory.Start.QuadPart,d->u.Memory.Length,
   !(d->Flags&CM_RESOURCE_MEMORY_READ_ONLY),0,d->ShareDisposition};
 }
 return 0;
}
NTSTATUS Op184Prepare(WDFDEVICE device,WDFCMRESLIST raw,WDFCMRESLIST translated)
{
 OP184_CONTEXT*c=Op184Context(device);OP182_RESOURCE r[OP182_RESOURCE_COUNT],t[OP182_RESOURCE_COUNT];NTSTATUS status=STATUS_DEVICE_CONFIGURATION_ERROR;Op184Lock(c);
 if(c->Data.MapCount||c->Data.Prepared||c->Data.Fault||c->Data.Busy||c->Data.Queued){status=STATUS_INVALID_DEVICE_STATE;goto done;}
 if(c->Data.MapCalls>UINT64_MAX-OP182_RESOURCE_COUNT||c->Data.UnmapCalls>UINT64_MAX-OP182_RESOURCE_COUNT){status=STATUS_INTEGER_OVERFLOW;goto done;}
 if(c->Data.PrepareEpoch==UINT64_MAX){status=STATUS_INTEGER_OVERFLOW;goto done;}c->Data.PrepareEpoch++;
 c->Data.ValidationCode=0;
 if(!Identity(c)){c->Data.ValidationCode=20;goto done;}
 c->Data.ValidationCode=Convert(raw,r);if(c->Data.ValidationCode)goto done;
 c->Data.ValidationCode=Convert(translated,t);if(c->Data.ValidationCode)goto done;
 c->Data.ValidationCode=Op182Validate(r,t,OP182_RESOURCE_COUNT);if(c->Data.ValidationCode)goto done;
 if(!NoManagedRam()){c->Data.ValidationCode=21;goto done;}
 for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=(LONGLONG)OP182Expected[i].Base;
  ULONG protection=(OP182Expected[i].Write?PAGE_READWRITE:PAGE_READONLY)|(OP182Expected[i].Cache?0:PAGE_NOCACHE);
  c->Data.MapCalls++;c->Maps[i]=MmMapIoSpaceEx(a,OP182Expected[i].Bytes,protection);
  if(!c->Maps[i]){c->Data.ValidationCode=22;status=STATUS_INSUFFICIENT_RESOURCES;Unmap(c);goto done;}c->Data.MapCount++;
 }
 c->Data.Prepared=1;status=STATUS_SUCCESS;
 done:c->Data.LastStatus=(ULONG)status;Op184Unlock(c);return status;
}
static int Available(void*x){return !InterlockedCompareExchange(&((OP184_CONTEXT*)x)->Cancel,0,0);}
static PULONG Address(OP184_CONTEXT*c,uint32_t at,int write)
{
 if(at&3)return NULL;
 for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){
  const OP182_RESOURCE*r=OP182Expected+i;
  if((uint64_t)at>=r->Base&&(uint64_t)at-r->Base<=r->Bytes-4&&(!write||r->Write)&&c->Maps[i])return(PULONG)((PUCHAR)c->Maps[i]+((uint64_t)at-r->Base));
 }
 return NULL;
}
static int RegRead(void*x,uint32_t at,uint32_t*v){PULONG p=Address(x,at,0);if(!p)return 0;*v=READ_REGISTER_ULONG(p);return 1;}
static int RegWrite(void*x,uint32_t at,uint32_t v){PULONG p=Address(x,at,1);if(!p)return 0;WRITE_REGISTER_ULONG(p,v);return 1;}
static uint64_t NowUs(void*x){OP184_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG n=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return n/c->Frequency*1000000+(n%c->Frequency)*1000000/c->Frequency;}
static uint64_t Now100ns(void*x){UNREFERENCED_PARAMETER(x);return KeQueryInterruptTime();}
static void DelayUs(void*x,uint32_t us){UNREFERENCED_PARAMETER(x);if(us==1||us==20)KeStallExecutionProcessor(us);}
static void WaitInterval(void*x){LARGE_INTEGER d;UNREFERENCED_PARAMETER(x);d.QuadPart=-200000;KeDelayExecutionThread(KernelMode,FALSE,&d);}
/* All state calls below hold Lock. Hardware runs only in the single work item;
 * stop invalidates first,then cancels/flushes outside Lock,before any unmap. */
static void Queue(OP184_CONTEXT*c)
{
 if(!c->Data.D0Active||c->Data.Fault||c->Data.Busy||c->Data.Queued||!Available(c))return;
 if(c->Data.Attempts==UINT64_MAX){c->Data.Fault=1;c->Data.Valid=0;return;}
 uint64_t now=KeQueryInterruptTime();if(now<c->NextDue100ns)return;
 if(now>UINT64_MAX-UINT64_C(50000000)){c->Data.Fault=1;c->Data.Valid=0;return;}
 c->NextDue100ns=now+UINT64_C(50000000);c->Data.Attempts++;c->Data.Queued=1;WdfWorkItemEnqueue(c->Work);
}
VOID Op184Timer(WDFTIMER timer)
{
 OP184_CONTEXT*c=Op184Context((WDFDEVICE)WdfTimerGetParentObject(timer));Op184Lock(c);
 if(c->Data.D0Active&&Available(c)){
  if(c->Data.Ticks!=UINT64_MAX)c->Data.Ticks++;
  uint64_t now=KeQueryInterruptTime();
  if(c->Data.Valid&&(now<c->Latest->End100ns||now-c->Latest->End100ns>S183_TTL_100NS))c->Data.Valid=0;
  if(!c->Data.Fault)Queue(c);WdfTimerStart(c->Timer,WDF_REL_TIMEOUT_IN_MS(1000));
 }
 Op184Unlock(c);
}
VOID Op184Worker(WDFWORKITEM item)
{
 OP184_CONTEXT*c=Op184Context((WDFDEVICE)WdfWorkItemGetParentObject(item));uint64_t epoch,sequence;S183_READING reading;uint32_t result;
 Op184Lock(c);c->Data.Queued=0;
 if(!c->Data.D0Active||c->Data.Fault||!Available(c)){Op184Unlock(c);return;}
 NT_ASSERT(!c->Data.Busy);c->Data.Busy=1;epoch=c->Data.D0Epoch;sequence=c->Data.Attempts;Op184Unlock(c);
 S183_IO io={c,RegRead,RegWrite,Available,NowUs,Now100ns,DelayUs,WaitInterval};
 S183Capture(&io,epoch,sequence,c->Working);result=S183Validate(c->Working,&reading);
 Op184Lock(c);c->Data.Busy=0;if(c->Data.Completed!=UINT64_MAX)c->Data.Completed++;
 /* The result belongs to this acquisition even when stop won; never publish
  * a cancelled/prior-epoch batch as current. Keep the raw attempt for evidence. */
 RtlCopyMemory(c->Latest,c->Working,sizeof(*c->Latest));c->Data.LastSequence=sequence;
 if(c->Working->Uncertain)c->Data.Uncertain=1;
 if(result){if(!(c->Working->CancelledClean&&!c->Data.D0Active&&!Available(c)&&!c->Working->Uncertain))c->Data.Fault=1;c->Data.Valid=0;c->Data.ValidationCode=result;RtlZeroMemory(&c->Reading,sizeof(c->Reading));}
 else if(c->Data.D0Active&&Available(c)&&c->Data.D0Epoch==epoch){c->Reading=reading;c->Data.Valid=1;c->Data.ValidCount++;c->Data.ValidationCode=0;}
 else{c->Data.Valid=0;RtlZeroMemory(&c->Reading,sizeof(c->Reading));}
 Op184Unlock(c);
}
static void Stop(OP184_CONTEXT*c)
{
 Op184Lock(c);c->Data.Valid=0;c->Data.D0Active=0;InterlockedExchange(&c->Cancel,1);Op184Unlock(c);
 WdfTimerStop(c->Timer,TRUE);WdfWorkItemFlush(c->Work);
 Op184Lock(c);NT_ASSERT(!c->Data.Busy);c->Data.Queued=0;Op184Unlock(c);
}
NTSTATUS Op184D0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 UNREFERENCED_PARAMETER(previous);OP184_CONTEXT*c=Op184Context(device);NTSTATUS s=STATUS_DEVICE_NOT_READY;Op184Lock(c);
 if(c->Data.Prepared&&c->Data.MapCount==OP182_RESOURCE_COUNT&&!c->Data.Fault&&!c->Data.Busy&&!c->Data.Queued&&c->Data.D0Epoch!=UINT64_MAX){c->Data.D0Epoch++;c->Data.ValidationCode=0;c->Data.D0Active=1;c->Data.Valid=0;InterlockedExchange(&c->Cancel,0);c->NextDue100ns=0;Queue(c);WdfTimerStart(c->Timer,WDF_REL_TIMEOUT_IN_MS(1000));s=STATUS_SUCCESS;}
 c->Data.ProducerQualified=0;c->Data.LastStatus=(ULONG)s;Op184Unlock(c);return s;
}
NTSTATUS Op184D0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE next){UNREFERENCED_PARAMETER(next);Stop(Op184Context(device));return STATUS_SUCCESS;}
NTSTATUS Op184Release(WDFDEVICE device,WDFCMRESLIST resources)
{
 UNREFERENCED_PARAMETER(resources);OP184_CONTEXT*c=Op184Context(device);Stop(c);Op184Lock(c);ULONG before=c->Data.MapCount;Unmap(c);if(c->Data.ReleaseCalls!=UINT64_MAX)c->Data.ReleaseCalls++;
 DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"G184 release maps_before=%lu maps_after=%lu map_calls=%I64u unmap_calls=%I64u busy=%lu queued=%lu valid=%lu fault=%lu uncertain=%lu\n",before,c->Data.MapCount,c->Data.MapCalls,c->Data.UnmapCalls,c->Data.Busy,c->Data.Queued,c->Data.Valid,c->Data.Fault,c->Data.Uncertain);
 Op184Unlock(c);return STATUS_SUCCESS;
}
VOID Op184Control(WDFQUEUE queue,WDFREQUEST request,size_t outBytes,size_t inBytes,ULONG code)
{
 OP184_REQUEST*input,in;OP184_SNAPSHOT*out;NTSTATUS s;ULONG_PTR bytes=0;
 if(code!=OP184_STATUS){s=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inBytes!=sizeof(in)){s=STATUS_INVALID_PARAMETER;goto done;}
 s=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(s))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=1||in.Magic!=OP184_MAGIC||in.Nonce||in.Count||in.Reserved){s=STATUS_INVALID_PARAMETER;goto done;}
 if(outBytes!=sizeof(*out)){s=STATUS_BUFFER_TOO_SMALL;goto done;}
 s=WdfRequestRetrieveOutputBuffer(request,sizeof(*out),(PVOID*)&out,NULL);if(!NT_SUCCESS(s))goto done;
 OP184_CONTEXT*c=Op184Context(WdfIoQueueGetDevice(queue));Op184Lock(c);uint64_t now=KeQueryInterruptTime();
 if(c->Data.Valid&&(now<c->Latest->End100ns||now-c->Latest->End100ns>S183_TTL_100NS))c->Data.Valid=0;
 c->Data.Now100ns=now;c->Data.Irql=KeGetCurrentIrql();RtlZeroMemory(out,sizeof(*out));out->Status=c->Data;
 if(c->Data.Valid)out->Reading=c->Reading;
 RtlCopyMemory(&out->Result,c->Latest,sizeof(out->Result));Op184Unlock(c);s=STATUS_SUCCESS;bytes=sizeof(*out);
 done:WdfRequestCompleteWithInformation(request,s,bytes);
}
VOID Op184FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file){UNREFERENCED_PARAMETER(device);PUNICODE_STRING name=WdfFileObjectGetFileName(file);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
NTSTATUS Op184Add(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 UNREFERENCED_PARAMETER(driver);WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_PNPPOWER_EVENT_CALLBACKS pnp;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;WDF_WORKITEM_CONFIG work;WDF_TIMER_CONFIG timer;NTSTATUS s;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);pnp.EvtDevicePrepareHardware=Op184Prepare;pnp.EvtDeviceReleaseHardware=Op184Release;pnp.EvtDeviceD0Entry=Op184D0Entry;pnp.EvtDeviceD0Exit=Op184D0Exit;WdfDeviceInitSetPnpPowerEventCallbacks(init,&pnp);
 WDF_FILEOBJECT_CONFIG_INIT(&file,Op184FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr,OP184_CONTEXT);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeNone;s=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(s))return s;
 OP184_CONTEXT*c=Op184Context(device);c->Data.Size=sizeof(OP184_SNAPSHOT);c->Data.Version=1;c->Data.Magic=OP184_MAGIC;c->Data.Instance=KeQueryInterruptTime();c->Cancel=1;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ParentObject=device;s=WdfWaitLockCreate(&attr,&c->Lock);if(!NT_SUCCESS(s))return s;
 s=WdfMemoryCreate(&attr,NonPagedPoolNx,'31GO',sizeof(*c->Working),&c->WorkingMemory,(PVOID*)&c->Working);if(!NT_SUCCESS(s))return s;
 s=WdfMemoryCreate(&attr,NonPagedPoolNx,'31GO',sizeof(*c->Latest),&c->LatestMemory,(PVOID*)&c->Latest);if(!NT_SUCCESS(s))return s;
 RtlZeroMemory(c->Working,sizeof(*c->Working));RtlZeroMemory(c->Latest,sizeof(*c->Latest));
 WDF_WORKITEM_CONFIG_INIT(&work,Op184Worker);work.AutomaticSerialization=FALSE;s=WdfWorkItemCreate(&work,&attr,&c->Work);if(!NT_SUCCESS(s))return s;
 WDF_TIMER_CONFIG_INIT(&timer,Op184Timer);timer.AutomaticSerialization=FALSE;s=WdfTimerCreate(&timer,&attr,&c->Timer);if(!NT_SUCCESS(s))return s;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=Op184Control;s=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(s))return s;
 return WdfDeviceCreateDeviceInterface(device,&Interface,NULL);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path){WDF_DRIVER_CONFIG config;WDF_DRIVER_CONFIG_INIT(&config,Op184Add);NTSTATUS s=AuxKlibInitialize();if(!NT_SUCCESS(s))return s;return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);}
