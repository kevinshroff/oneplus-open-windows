/* Explicit OS/WDF/resource/mapping model for the actual driver source. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include "resources.h"
typedef int32_t NTSTATUS;typedef uint32_t ULONG;typedef uintptr_t ULONG_PTR;typedef uint8_t UCHAR;typedef int64_t LONGLONG;typedef void VOID,*PVOID,*PDRIVER_OBJECT,*WDFDRIVER,*PWDFDEVICE_INIT,*WDFFILEOBJECT;
typedef struct{LONGLONG QuadPart;}LARGE_INTEGER,PHYSICAL_ADDRESS;
typedef struct{PHYSICAL_ADDRESS BaseAddress;LARGE_INTEGER NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
typedef struct{unsigned short Length;const wchar_t*Buffer;}UNICODE_STRING,*PUNICODE_STRING;
typedef struct{ULONG dwOSVersionInfoSize,dwBuildNumber;}RTL_OSVERSIONINFOW;
typedef struct{uint32_t Data1;uint16_t Data2,Data3;uint8_t Data4[8];}GUID;
typedef struct{unsigned char Type,ShareDisposition;unsigned short Flags;union{struct{PHYSICAL_ADDRESS Start;ULONG Length;}Memory;}u;}CM_PARTIAL_RESOURCE_DESCRIPTOR,*PCM_PARTIAL_RESOURCE_DESCRIPTOR;
typedef struct{unsigned Count,NullIndex;CM_PARTIAL_RESOURCE_DESCRIPTOR Descriptors[20];}MODEL_RESOURCES,*WDFCMRESLIST;
typedef struct{pthread_mutex_t Mutex;}MODEL_LOCK,*WDFWAITLOCK;
typedef struct{max_align_t Align;uint8_t Context[1024];WDFWAITLOCK Lock;}MODEL_DEVICE,*WDFDEVICE,*WDFQUEUE;
typedef struct{uint8_t Buffer[112];size_t Capacity,Bytes;NTSTATUS InputStatus,OutputStatus,Status;}MODEL_REQUEST,*WDFREQUEST;
typedef unsigned WDF_POWER_DEVICE_STATE;
typedef NTSTATUS DRIVER_INITIALIZE(PDRIVER_OBJECT,PUNICODE_STRING);
typedef NTSTATUS EVT_WDF_DRIVER_DEVICE_ADD(WDFDRIVER,PWDFDEVICE_INIT);
typedef NTSTATUS EVT_WDF_DEVICE_PREPARE_HARDWARE(WDFDEVICE,WDFCMRESLIST,WDFCMRESLIST);
typedef NTSTATUS EVT_WDF_DEVICE_RELEASE_HARDWARE(WDFDEVICE,WDFCMRESLIST);
typedef NTSTATUS EVT_WDF_DEVICE_D0_ENTRY(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef NTSTATUS EVT_WDF_DEVICE_D0_EXIT(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef VOID EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL(WDFQUEUE,WDFREQUEST,size_t,size_t,ULONG);
typedef VOID EVT_WDF_DEVICE_FILE_CREATE(WDFDEVICE,WDFREQUEST,WDFFILEOBJECT);
#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(t,n) static t*n(WDFDEVICE d){assert(d);return(t*)d->Context;}
#define C_ASSERT(x) _Static_assert(x,#x)
#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22u
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_DEVICE_SECURE_OPEN 0x100
#define STATUS_SUCCESS 0
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)-1)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)-2)
#define STATUS_INTEGER_OVERFLOW ((NTSTATUS)-3)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)-4)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)-5)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)-6)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)-7)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)-8)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)-9)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define PASSIVE_LEVEL 0
#define TRUE 1
#define ALL_PROCESSOR_GROUPS 0xffff
#define PAGE_READONLY 1
#define PAGE_READWRITE 2
#define PAGE_NOCACHE 4
#define CmResourceTypeMemory 3
#define CM_RESOURCE_MEMORY_READ_ONLY 1
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define NT_ASSERT(x) assert(x)
#define RtlCopyMemory memcpy
static size_t RtlCompareMemory(const void*a,const void*b,size_t n){const uint8_t*x=a,*y=b;size_t i=0;while(i<n&&x[i]==y[i])i++;return i;}
static unsigned Build=26100,Cpus=8,VersionFailure,FirmwareFailure,BadFirmware,BadFirmwareSize,MissingRam,MalformedRam,OverflowRam;
static _Thread_local unsigned Irql,LockHeld;
static uint64_t RamAt;static _Atomic uint64_t Clock=1000000;
static unsigned KeGetCurrentIrql(void){return Irql;}
static unsigned KeQueryActiveProcessorCountEx(unsigned g){assert(g==ALL_PROCESSOR_GROUPS);return Cpus;}
static uint64_t KeQueryInterruptTime(void){return atomic_fetch_add(&Clock,1000)+1000;}
static NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*v){assert(v->dwOSVersionInfoSize==sizeof(*v));if(VersionFailure)return-1;v->dwBuildNumber=Build;return 0;}
static const UCHAR ClnExpectedDsdt[576];
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG provider,ULONG table,void*b,ULONG n,ULONG*got){assert(provider==0x41435049&&table==0x54445344&&n==576);if(FirmwareFailure)return-1;memcpy(b,ClnExpectedDsdt,576);if(BadFirmware)((uint8_t*)b)[0]^=1;*got=BadFirmwareSize?575:576;return 0;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(void*p,unsigned flags){assert(!p&&!flags);if(MissingRam)return NULL;PPHYSICAL_MEMORY_RANGE r=calloc(512,sizeof(*r));assert(r);if(RamAt){r[0].BaseAddress.QuadPart=(LONGLONG)RamAt;r[0].NumberOfBytes.QuadPart=4096;}if(MalformedRam)for(unsigned i=0;i<512;i++){r[i].BaseAddress.QuadPart=0x10000+(LONGLONG)i*4096;r[i].NumberOfBytes.QuadPart=1;}if(OverflowRam){r[0].BaseAddress.QuadPart=(LONGLONG)(UINT64_MAX-100);r[0].NumberOfBytes.QuadPart=200;}return r;}
static void ExFreePool(void*p){free(p);}
typedef struct{void*Buffer;size_t Bytes;unsigned Expected;}MODEL_MAP;
static MODEL_MAP Maps[20];static unsigned LiveMaps,MapAttempts,UnmapAttempts,FailMap;
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,size_t n,ULONG protection){assert(LockHeld);unsigned j;for(j=0;j<20;j++)if(OP182Expected[j].Base==(uint64_t)a.QuadPart)break;assert(j<20&&n==OP182Expected[j].Bytes&&protection==((OP182Expected[j].Write?2u:1u)|(OP182Expected[j].Cache?0u:4u)));if(++MapAttempts==FailMap)return NULL;assert(!Maps[j].Buffer);void*b=malloc(n);assert(b);memset(b,0xa5,n);Maps[j]=(MODEL_MAP){b,n,j};LiveMaps++;return b;}
static void MmUnmapIoSpace(void*b,size_t n){assert(LockHeld);unsigned j;for(j=0;j<20;j++)if(Maps[j].Buffer==b)break;assert(j<20&&Maps[j].Bytes==n);for(size_t i=0;i<n;i++)assert(((uint8_t*)b)[i]==0xa5);free(b);Maps[j].Buffer=NULL;LiveMaps--;UnmapAttempts++;}
static unsigned WdfCmResourceListGetCount(WDFCMRESLIST l){assert(l);return l->Count;}
static PCM_PARTIAL_RESOURCE_DESCRIPTOR WdfCmResourceListGetDescriptor(WDFCMRESLIST l,unsigned i){assert(i<20&&i<l->Count);return l->NullIndex==i?NULL:l->Descriptors+i;}
#define WDF_NO_EVENT_CALLBACK NULL
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define WDF_NO_HANDLE NULL
#define WdfDeviceIoBuffered 1
#define WdfExecutionLevelPassive 1
#define WdfSynchronizationScopeNone 0
#define WdfIoQueueDispatchSequential 1
#define WdfFalse 0
#define WDF_OBJECT_ATTRIBUTES_INIT(a) memset(a,0,sizeof(*(a)))
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(a,t) do{WDF_OBJECT_ATTRIBUTES_INIT(a);(a)->ContextBytes=sizeof(t);}while(0)
#define WDF_PNPPOWER_EVENT_CALLBACKS_INIT(p) memset(p,0,sizeof(*(p)))
#define WDF_FILEOBJECT_CONFIG_INIT(f,c,x,y) do{(f)->Create=c;assert(!(x)&&!(y));}while(0)
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(q,d) do{assert(d==1);memset(q,0,sizeof(*(q)));}while(0)
#define WDF_DRIVER_CONFIG_INIT(c,a) do{memset(c,0,sizeof(*(c)));(c)->Add=a;}while(0)
typedef struct{void*ParentObject;unsigned ExecutionLevel,SynchronizationScope;size_t ContextBytes;}WDF_OBJECT_ATTRIBUTES;
typedef struct{EVT_WDF_DEVICE_PREPARE_HARDWARE*EvtDevicePrepareHardware;EVT_WDF_DEVICE_RELEASE_HARDWARE*EvtDeviceReleaseHardware;EVT_WDF_DEVICE_D0_ENTRY*EvtDeviceD0Entry;EVT_WDF_DEVICE_D0_EXIT*EvtDeviceD0Exit;}WDF_PNPPOWER_EVENT_CALLBACKS;
typedef struct{EVT_WDF_DEVICE_FILE_CREATE*Create;}WDF_FILEOBJECT_CONFIG;
typedef struct{unsigned PowerManaged;EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL*EvtIoDeviceControl;}WDF_IO_QUEUE_CONFIG;
typedef struct{EVT_WDF_DRIVER_DEVICE_ADD*Add;}WDF_DRIVER_CONFIG;
static unsigned EntrySteps,FailEntry;static WDFDEVICE Device;
static int EntryOK(void){return++EntrySteps!=FailEntry;}
static NTSTATUS AuxKlibInitialize(void){return EntryOK()?0:-4;}
static NTSTATUS WdfDriverCreate(void*o,void*p,void*a,WDF_DRIVER_CONFIG*c,void*out){assert(o&&p&&!a&&c->Add&&!out);return EntryOK()?0:-4;}
static void WdfDeviceInitSetDeviceType(void*i,unsigned t){assert(i&&t==0x22);}
static void WdfDeviceInitSetCharacteristics(void*i,unsigned v,unsigned b){assert(i&&v==0x100&&b);}
static void WdfDeviceInitSetIoType(void*i,unsigned v){assert(i&&v==1);}
static void WdfDeviceInitSetPnpPowerEventCallbacks(void*i,WDF_PNPPOWER_EVENT_CALLBACKS*p){assert(i&&p->EvtDevicePrepareHardware&&p->EvtDeviceReleaseHardware&&p->EvtDeviceD0Entry&&p->EvtDeviceD0Exit);}
static void WdfDeviceInitSetFileObjectConfig(void*i,WDF_FILEOBJECT_CONFIG*f,void*a){assert(i&&f->Create&&!a);}
static NTSTATUS WdfDeviceCreate(void**init,WDF_OBJECT_ATTRIBUTES*a,WDFDEVICE*out){assert(*init&&a->ContextBytes<=1024&&a->ExecutionLevel==1&&a->SynchronizationScope==0&&!Device);if(!EntryOK())return-4;Device=calloc(1,sizeof(*Device));assert(Device);*out=Device;*init=NULL;return 0;}
static NTSTATUS WdfWaitLockCreate(WDF_OBJECT_ATTRIBUTES*a,WDFWAITLOCK*out){assert(a->ParentObject==Device);if(!EntryOK())return-4;MODEL_LOCK*l=calloc(1,sizeof(*l));assert(l&&!pthread_mutex_init(&l->Mutex,NULL));Device->Lock=l;*out=l;return 0;}
static NTSTATUS WdfWaitLockAcquire(WDFWAITLOCK l,void*timeout){assert(l&&!timeout&&!LockHeld&&!Irql);assert(!pthread_mutex_lock(&l->Mutex));LockHeld=1;return 0;}
static void WdfWaitLockRelease(WDFWAITLOCK l){assert(l&&LockHeld);LockHeld=0;assert(!pthread_mutex_unlock(&l->Mutex));}
#define DPFLTR_IHVDRIVER_ID 77
#define DPFLTR_ERROR_LEVEL 0
static ULONG DbgPrintEx(ULONG id,ULONG level,const char*format,...){assert(id==77&&!level&&LockHeld&&strstr(format,"G182 release"));va_list ap;va_start(ap,format);ULONG before=va_arg(ap,ULONG),after=va_arg(ap,ULONG);uint64_t maps=va_arg(ap,uint64_t),unmaps=va_arg(ap,uint64_t),releases=va_arg(ap,uint64_t);ULONG prepared=va_arg(ap,ULONG),producer=va_arg(ap,ULONG);va_end(ap);assert(before<=20&&!after&&!LiveMaps&&maps>=unmaps&&releases&&!prepared&&!producer);return 0;}
static NTSTATUS WdfIoQueueCreate(WDFDEVICE d,WDF_IO_QUEUE_CONFIG*q,void*a,void*out){assert(d==Device&&!q->PowerManaged&&q->EvtIoDeviceControl&&!a&&!out);return EntryOK()?0:-4;}
static NTSTATUS WdfDeviceCreateDeviceInterface(WDFDEVICE d,const GUID*g,void*s){assert(d==Device&&g->Data1==0x8fa58182&&!s);return EntryOK()?0:-4;}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){assert(q==Device);return q;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,void**b,void*z){assert(n==32&&!z);if(!r->InputStatus)*b=r->Buffer;return r->InputStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,void**b,void*z){assert(n==112&&n<=r->Capacity&&!z);if(!r->OutputStatus)*b=r->Buffer;return r->OutputStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,size_t n){r->Status=s;r->Bytes=n;}
static void WdfRequestComplete(WDFREQUEST r,NTSTATUS s){WdfRequestCompleteWithInformation(r,s,0);}
static PUNICODE_STRING WdfFileObjectGetFileName(WDFFILEOBJECT f){return f;}
