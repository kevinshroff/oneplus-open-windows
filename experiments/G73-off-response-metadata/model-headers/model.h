/* SPDX-License-Identifier: MIT -- API contract model; not Windows headers. */
#ifndef G73_MODEL_H
#define G73_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <wchar.h>
typedef int32_t NTSTATUS,LONG;typedef int64_t LONG64,LONGLONG;typedef uint64_t ULONGLONG,ULONG_PTR;typedef uint32_t ULONG;typedef uint8_t UCHAR;typedef size_t SIZE_T;typedef void VOID;typedef void*PVOID;typedef UCHAR*PUCHAR;typedef ULONG*PULONG;typedef void*PDRIVER_OBJECT;
typedef struct{uint16_t Length,MaximumLength;const wchar_t*Buffer;}UNICODE_STRING,*PUNICODE_STRING;
typedef struct{int64_t QuadPart;}PHYSICAL_ADDRESS,LARGE_INTEGER;
typedef struct{ULONG dwOSVersionInfoSize,dwBuildNumber;}RTL_OSVERSIONINFOW;
typedef void*WDFDRIVER;typedef void*WDFDEVICE;typedef void*WDFQUEUE;
typedef struct{int Live,Exclusive,Io,DeviceType,Characteristics;void*Create;}ModelInit;typedef ModelInit*PWDFDEVICE_INIT;
typedef struct{UNICODE_STRING Name;}ModelFile;typedef ModelFile*WDFFILEOBJECT;
typedef struct{void*Input,*Output;size_t InputBytes,OutputBytes;NTSTATUS Status;size_t Info;int Complete,FailInput,FailOutput;}ModelRequest;typedef ModelRequest*WDFREQUEST;
typedef NTSTATUS DRIVER_INITIALIZE(PDRIVER_OBJECT,PUNICODE_STRING);typedef VOID EVT_WDF_DRIVER_UNLOAD(WDFDRIVER);typedef VOID EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL(WDFQUEUE,WDFREQUEST,size_t,size_t,ULONG);typedef VOID EVT_WDF_DEVICE_FILE_CREATE(WDFDEVICE,WDFREQUEST,WDFFILEOBJECT);
typedef struct{int DriverInitFlags;EVT_WDF_DRIVER_UNLOAD*EvtDriverUnload;}WDF_DRIVER_CONFIG;
typedef struct{int ExecutionLevel,SynchronizationScope;}WDF_OBJECT_ATTRIBUTES;
typedef struct{int Dispatch,PowerManaged;EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL*EvtIoDeviceControl;}WDF_IO_QUEUE_CONFIG;
typedef struct{EVT_WDF_DEVICE_FILE_CREATE*Create;}WDF_FILEOBJECT_CONFIG;
#define STATUS_SUCCESS 0
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xc0000033)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_NOT_FOUND ((NTSTATUS)0xc0000225)
#define STATUS_QUOTA_EXCEEDED ((NTSTATUS)0xc0000044)
#define NT_SUCCESS(x) ((NTSTATUS)(x)>=0)
#define PASSIVE_LEVEL 0
#define ALL_PROCESSOR_GROUPS 0xffff
#define TRUE 1
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 0x200
#define FILE_DEVICE_UNKNOWN 0x22
#define FILE_DEVICE_SECURE_OPEN 0x100
#define POOL_FLAG_NON_PAGED 0x40
#define WdfDriverInitNonPnpDriver 1
#define WdfDeviceIoBuffered 1
#define WdfExecutionLevelPassive 1
#define WdfSynchronizationScopeDevice 1
#define WdfIoQueueDispatchSequential 1
#define WdfFalse 0
#define WDF_NO_EVENT_CALLBACK NULL
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define RTL_NUMBER_OF(x) (sizeof(x)/sizeof((x)[0]))
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory(d,s,n) memcpy(d,s,n)
#define DECLARE_CONST_UNICODE_STRING(n,s) const UNICODE_STRING n={(sizeof(s)/sizeof(wchar_t)-1)*2,sizeof(s)/sizeof(wchar_t)*2,s}
#define WDF_DRIVER_CONFIG_INIT(p,a) do{assert(!(a));memset(p,0,sizeof(*(p)));}while(0)
#define WDF_OBJECT_ATTRIBUTES_INIT(p) memset(p,0,sizeof(*(p)))
#define WDF_FILEOBJECT_CONFIG_INIT(p,c,cl,cu) do{assert(!(cl)&&!(cu));(p)->Create=c;}while(0)
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(p,d) do{memset(p,0,sizeof(*(p)));(p)->Dispatch=d;}while(0)
static ULONG Build=26100,Processors=8,Irql,FirmwareBytes=576;static int FirmwareFlip,EntryFail;static NTSTATUS FirmwareStatus;
static unsigned Maps,Unmaps,FailMap,Allocations,Frees,InitFrees,Finished,DriverCreates,FirmwareQueries,VersionCalls;static void*Allocation;static size_t AllocationBytes;static ModelInit Init;static WDF_IO_QUEUE_CONFIG Queue;
static uint64_t Ticks;
static ULONG KeQueryActiveProcessorCountEx(ULONG n){assert(n==ALL_PROCESSOR_GROUPS);return Processors;}
static ULONG KeGetCurrentIrql(void){return Irql;}
static uint64_t KeQueryInterruptTime(void){return ++Ticks;}
static LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*f){if(f)f->QuadPart=19200000;Ticks+=19200;return(LARGE_INTEGER){(int64_t)Ticks};}
static NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*v){assert(!Irql&&v->dwOSVersionInfoSize==sizeof(*v));VersionCalls++;v->dwBuildNumber=Build;return 0;}
static size_t RtlCompareMemory(const void*a,const void*b,size_t n){const UCHAR*x=a,*y=b;size_t i;for(i=0;i<n&&x[i]==y[i];i++){}return i;}
static NTSTATUS AuxKlibInitialize(void){return EntryFail==2?STATUS_NOT_SUPPORTED:0;}
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG,ULONG,void*,ULONG,ULONG*);
static LONG InterlockedCompareExchange(volatile LONG*p,LONG n,LONG old){return __sync_val_compare_and_swap(p,old,n);}
static LONG InterlockedExchange(volatile LONG*p,LONG n){return __sync_lock_test_and_set(p,n);}
static LONG InterlockedIncrement(volatile LONG*p){return __sync_add_and_fetch(p,1);}
static LONG64 InterlockedIncrement64(volatile LONG64*p){return __sync_add_and_fetch(p,1);}
static void*ExAllocatePool2(ULONG flags,size_t n,ULONG tag){assert(flags==POOL_FLAG_NON_PAGED&&tag==0x3337474f&&!Allocation);if(EntryFail==3)return NULL;Allocation=calloc(1,n);assert(Allocation);AllocationBytes=n;Allocations++;return Allocation;}
static void ExFreePoolWithTag(void*p,ULONG tag){assert(p&&p==Allocation&&tag==0x3337474f);free(p);Allocation=NULL;AllocationBytes=0;Frees++;}
static NTSTATUS WdfDriverCreate(PDRIVER_OBJECT o,PUNICODE_STRING p,void*a,WDF_DRIVER_CONFIG*c,WDFDRIVER*d){assert(o&&p&&!a&&c->DriverInitFlags==1&&c->EvtDriverUnload&&d);DriverCreates++;if(EntryFail==1)return STATUS_NOT_SUPPORTED;*d=(void*)1;return 0;}
static PWDFDEVICE_INIT WdfControlDeviceInitAllocate(WDFDRIVER d,const UNICODE_STRING*s){assert(d&&s&&!wcscmp(s->Buffer,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"));if(EntryFail==4)return NULL;memset(&Init,0,sizeof(Init));Init.Live=1;return &Init;}
static void WdfDeviceInitSetDeviceType(PWDFDEVICE_INIT i,ULONG v){assert(i->Live&&v==0x22);i->DeviceType=v;}
static void WdfDeviceInitSetCharacteristics(PWDFDEVICE_INIT i,ULONG v,int t){assert(i->Live&&v==0x100&&t);i->Characteristics=v;}
static void WdfDeviceInitSetExclusive(PWDFDEVICE_INIT i,int v){assert(i->Live&&v);i->Exclusive=v;}
static void WdfDeviceInitSetIoType(PWDFDEVICE_INIT i,int v){assert(i->Live&&v==1);i->Io=v;}
static void WdfDeviceInitSetFileObjectConfig(PWDFDEVICE_INIT i,WDF_FILEOBJECT_CONFIG*f,void*a){assert(i->Live&&!a&&f->Create);i->Create=(void*)f->Create;}
static NTSTATUS WdfDeviceInitAssignName(PWDFDEVICE_INIT i,const UNICODE_STRING*s){assert(i->Live&&!wcscmp(s->Buffer,L"\\Device\\OpenG73"));return EntryFail==5?STATUS_NOT_SUPPORTED:0;}
static NTSTATUS WdfDeviceCreate(PWDFDEVICE_INIT*i,WDF_OBJECT_ATTRIBUTES*a,WDFDEVICE*d){assert(i&&(*i)->Live&&(*i)->Exclusive&&(*i)->Io&&(*i)->Create&&a->ExecutionLevel==1&&a->SynchronizationScope==1);if(EntryFail==6)return STATUS_NOT_SUPPORTED;(*i)->Live=0;*i=NULL;*d=(void*)2;return 0;}
static NTSTATUS WdfDeviceCreateSymbolicLink(WDFDEVICE d,const UNICODE_STRING*s){assert(d&&!wcscmp(s->Buffer,L"\\DosDevices\\OpenG73"));return EntryFail==7?STATUS_NOT_SUPPORTED:0;}
static NTSTATUS WdfIoQueueCreate(WDFDEVICE d,WDF_IO_QUEUE_CONFIG*q,void*a,void*out){assert(d&&!a&&!out&&q->Dispatch==1&&!q->PowerManaged&&q->EvtIoDeviceControl);Queue=*q;return EntryFail==8?STATUS_NOT_SUPPORTED:0;}
static void WdfControlFinishInitializing(WDFDEVICE d){assert(d&&Allocation&&Queue.EvtIoDeviceControl);Finished++;}
static void WdfDeviceInitFree(PWDFDEVICE_INIT i){assert(i->Live);i->Live=0;InitFrees++;}
static PUNICODE_STRING WdfFileObjectGetFileName(WDFFILEOBJECT f){return &f->Name;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,void**p,void*x){assert(!x);if(r->FailInput||r->InputBytes<n)return STATUS_BUFFER_TOO_SMALL;*p=r->Input;return 0;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,void**p,void*x){assert(!x);if(r->FailOutput||r->OutputBytes<n)return STATUS_BUFFER_TOO_SMALL;*p=r->Output;return 0;}
static void WdfRequestComplete(WDFREQUEST r,NTSTATUS s){assert(!r->Complete);r->Complete=1;r->Status=s;r->Info=0;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,size_t n){WdfRequestComplete(r,s);r->Info=n;}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS,size_t,ULONG);static void MmUnmapIoSpace(void*,size_t);static ULONG ModelRead(volatile ULONG*);static void ModelWrite(volatile ULONG*,ULONG);static void KeStallExecutionProcessor(ULONG);
#define READ_REGISTER_ULONG ModelRead
#define WRITE_REGISTER_ULONG ModelWrite
#endif
