/* SPDX-License-Identifier: MIT -- API contract model only, never a driver SDK. */
#ifndef G67_MODEL_H
#define G67_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
typedef int32_t NTSTATUS;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;typedef void VOID;typedef void*PVOID;typedef void*PDRIVER_OBJECT;
typedef struct{uint16_t Length;uint16_t MaximumLength;uint16_t*Buffer;}UNICODE_STRING,*PUNICODE_STRING;
typedef struct{ULONG dwOSVersionInfoSize;ULONG dwBuildNumber;}RTL_OSVERSIONINFOW;
typedef struct{uint32_t Data1;uint16_t Data2,Data3;uint8_t Data4[8];}GUID;
typedef struct{int64_t QuadPart;}PHYSICAL_ADDRESS;typedef UCHAR*PUCHAR;typedef int32_t LONG;
#pragma pack(push,4)
typedef union{UCHAR Bytes[20];struct{UCHAR Type,ShareDisposition;uint16_t Flags;union{struct{PHYSICAL_ADDRESS Start;ULONG Length;}Memory;UCHAR Reserved[16];}u;};}CM_PARTIAL_RESOURCE_DESCRIPTOR,*PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#pragma pack(pop)
typedef pthread_mutex_t*WDFWAITLOCK;
typedef void*WDFDEVICE;typedef void*WDFDRIVER;typedef void*PWDFDEVICE_INIT;typedef void*WDFQUEUE;typedef void*WDFFILEOBJECT;typedef int WDF_POWER_DEVICE_STATE;
typedef struct{ULONG Count;CM_PARTIAL_RESOURCE_DESCRIPTOR*Rows[12];}ModelList;typedef ModelList*WDFCMRESLIST;
typedef struct{void*Input;void*Output;size_t InputBytes,OutputBytes;NTSTATUS Complete;size_t Information;int Completed,FailInput,FailOutput;}ModelRequest;typedef ModelRequest*WDFREQUEST;
typedef NTSTATUS DRIVER_INITIALIZE(PDRIVER_OBJECT,PUNICODE_STRING);typedef NTSTATUS EVT_WDF_DRIVER_DEVICE_ADD(WDFDRIVER,PWDFDEVICE_INIT);
typedef NTSTATUS EVT_WDF_DEVICE_PREPARE_HARDWARE(WDFDEVICE,WDFCMRESLIST,WDFCMRESLIST);typedef NTSTATUS EVT_WDF_DEVICE_RELEASE_HARDWARE(WDFDEVICE,WDFCMRESLIST);
typedef NTSTATUS EVT_WDF_DEVICE_D0_ENTRY(WDFDEVICE,WDF_POWER_DEVICE_STATE);typedef NTSTATUS EVT_WDF_DEVICE_D0_EXIT(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef VOID EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL(WDFQUEUE,WDFREQUEST,size_t,size_t,ULONG);typedef VOID EVT_WDF_DEVICE_FILE_CREATE(WDFDEVICE,WDFREQUEST,WDFFILEOBJECT);
typedef struct{size_t ContextSize;int ExecutionLevel,SynchronizationScope;void*ParentObject;}WDF_OBJECT_ATTRIBUTES;
typedef VOID EVT_WDF_DEVICE_SURPRISE_REMOVAL(WDFDEVICE);
typedef struct{EVT_WDF_DEVICE_PREPARE_HARDWARE*EvtDevicePrepareHardware;EVT_WDF_DEVICE_RELEASE_HARDWARE*EvtDeviceReleaseHardware;EVT_WDF_DEVICE_D0_ENTRY*EvtDeviceD0Entry;EVT_WDF_DEVICE_D0_EXIT*EvtDeviceD0Exit;EVT_WDF_DEVICE_SURPRISE_REMOVAL*EvtDeviceSurpriseRemoval;}WDF_PNPPOWER_EVENT_CALLBACKS;
typedef struct{int Dispatch,PowerManaged;EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL*EvtIoDeviceControl;}WDF_IO_QUEUE_CONFIG;
typedef struct{EVT_WDF_DEVICE_FILE_CREATE*Create;void*Close;void*Cleanup;}WDF_FILEOBJECT_CONFIG;
typedef struct{EVT_WDF_DRIVER_DEVICE_ADD*Add;}WDF_DRIVER_CONFIG;
#define STATUS_SUCCESS 0
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xc0000033)
#define NT_SUCCESS(x) ((NTSTATUS)(x)>=0)
#define TRUE 1
#define FALSE 0
#define Executive 0
#define KernelMode 0
#define PASSIVE_LEVEL 0
#define ALL_PROCESSOR_GROUPS 0xffff
#define FILE_DEVICE_UNKNOWN 0x22
#define FILE_DEVICE_SECURE_OPEN 0x100
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 0x200
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xc0000182)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_DEVICE_HARDWARE_ERROR ((NTSTATUS)0xc0000483)
#define STATUS_QUOTA_EXCEEDED ((NTSTATUS)0xc0000044)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define WdfDeviceIoBuffered 1
#define WdfIoQueueDispatchSequential 1
#define WdfTrue 1
#define WdfExecutionLevelPassive 1
#define WdfSynchronizationScopeNone 0
#define WDF_NO_EVENT_CALLBACK NULL
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define WDF_NO_HANDLE NULL
#define NT_ASSERT assert
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory(d,s,n) memcpy(d,s,n)
#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(t,n) static t*n(WDFDEVICE d){return(t*)d;}
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(p,t) do{memset(p,0,sizeof(*(p)));(p)->ContextSize=sizeof(t);}while(0)
#define WDF_OBJECT_ATTRIBUTES_INIT(p) memset(p,0,sizeof(*(p)))
#define WDF_PNPPOWER_EVENT_CALLBACKS_INIT(p) memset(p,0,sizeof(*(p)))
#define WDF_FILEOBJECT_CONFIG_INIT(p,c,cl,cu) do{memset(p,0,sizeof(*(p)));(p)->Create=c;(p)->Close=cl;(p)->Cleanup=cu;}while(0)
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(p,d) do{memset(p,0,sizeof(*(p)));(p)->Dispatch=d;}while(0)
#define WDF_DRIVER_CONFIG_INIT(p,a) do{memset(p,0,sizeof(*(p)));(p)->Add=a;}while(0)
static ULONG Build=26100,Processors=8,Irql=0,FirmwareBytes=742;static NTSTATUS FirmwareStatus,AuxStatus,QueueStatus;static int FirmwareFlip,DeviceCreates,DriverCreates,Interfaces;static WDFDEVICE Device;static WDF_PNPPOWER_EVENT_CALLBACKS Callbacks;static GUID Interface;static WDF_IO_QUEUE_CONFIG Queue;static WDF_FILEOBJECT_CONFIG Files;
static ULONG KeQueryActiveProcessorCountEx(ULONG n){assert(n==ALL_PROCESSOR_GROUPS);return Processors;}
static ULONG KeGetCurrentIrql(void){return Irql;}
static NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*v){assert(v->dwOSVersionInfoSize==sizeof(*v));v->dwBuildNumber=Build;return 0;}
static size_t RtlCompareMemory(const void*a,const void*b,size_t n){const UCHAR*x=a,*y=b;size_t i;for(i=0;i<n&&x[i]==y[i];i++){}return i;}
static NTSTATUS AuxKlibInitialize(void){return AuxStatus;}
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG,ULONG,void*,ULONG,ULONG*);
static void WdfDeviceInitSetDeviceType(PWDFDEVICE_INIT i,ULONG v){assert(i&&v==FILE_DEVICE_UNKNOWN);}
static void WdfDeviceInitSetCharacteristics(PWDFDEVICE_INIT i,ULONG v,int a){assert(i&&v==FILE_DEVICE_SECURE_OPEN&&a);}
static void WdfDeviceInitSetExclusive(PWDFDEVICE_INIT i,int v){assert(i&&v);}
static void WdfDeviceInitSetIoType(PWDFDEVICE_INIT i,int v){assert(i&&v==WdfDeviceIoBuffered);}
static void WdfDeviceInitSetFileObjectConfig(PWDFDEVICE_INIT i,WDF_FILEOBJECT_CONFIG*f,void*a){assert(i&&!a);Files=*f;}
static void WdfDeviceInitSetPnpPowerEventCallbacks(PWDFDEVICE_INIT i,WDF_PNPPOWER_EVENT_CALLBACKS*p){assert(i);Callbacks=*p;}
static NTSTATUS WdfDeviceCreate(PWDFDEVICE_INIT*i,WDF_OBJECT_ATTRIBUTES*a,WDFDEVICE*d){assert(i&&*i&&a->ExecutionLevel==1&&a->SynchronizationScope==0&&!Device);Device=calloc(1,a->ContextSize);assert(Device);*d=Device;DeviceCreates++;return 0;}
static NTSTATUS WdfIoQueueCreate(WDFDEVICE d,WDF_IO_QUEUE_CONFIG*q,void*a,void*o){assert(d==Device&&!a&&!o&&q->PowerManaged==1&&q->Dispatch==1);Queue=*q;return QueueStatus;}
static NTSTATUS WdfDeviceCreateDeviceInterface(WDFDEVICE d,const GUID*g,void*s){assert(d==Device&&!s);Interface=*g;Interfaces++;return 0;}
static ULONG WdfCmResourceListGetCount(WDFCMRESLIST l){return l?l->Count:0;}
static CM_PARTIAL_RESOURCE_DESCRIPTOR*WdfCmResourceListGetDescriptor(WDFCMRESLIST l,ULONG i){assert(l&&i<l->Count&&i<12);return l->Rows[i];}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){return q;}
static PUNICODE_STRING WdfFileObjectGetFileName(WDFFILEOBJECT f){return f;}
static void WdfRequestComplete(WDFREQUEST r,NTSTATUS s){assert(!r->Completed);r->Completed=1;r->Complete=s;r->Information=0;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,size_t n){WdfRequestComplete(r,s);r->Information=n;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,void**p,void*x){assert(!x);if(r->FailInput||r->InputBytes<n)return STATUS_BUFFER_TOO_SMALL;*p=r->Input;return 0;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,void**p,void*x){assert(!x);if(r->FailOutput||r->OutputBytes<n)return STATUS_BUFFER_TOO_SMALL;*p=r->Output;return 0;}
static NTSTATUS WdfDriverCreate(PDRIVER_OBJECT o,PUNICODE_STRING p,void*a,WDF_DRIVER_CONFIG*c,void*h){assert(o&&!p&&!a&&!h&&c->Add);DriverCreates++;return 0;}
static NTSTATUS WaitLockStatus;
static NTSTATUS WdfWaitLockCreate(WDF_OBJECT_ATTRIBUTES*a,WDFWAITLOCK*out){assert(a&&a->ParentObject==Device);if(WaitLockStatus)return WaitLockStatus;*out=malloc(sizeof(**out));assert(*out&&!pthread_mutex_init(*out,NULL));return 0;}
static NTSTATUS WdfWaitLockAcquire(WDFWAITLOCK p,void*t){assert(p&&!t&&!pthread_mutex_lock(p));return 0;}
static void WdfWaitLockRelease(WDFWAITLOCK p){assert(p&&!pthread_mutex_unlock(p));}
static LONG InterlockedCompareExchange(volatile LONG*p,LONG n,LONG old){return __sync_val_compare_and_swap(p,old,n);}
static LONG InterlockedExchange(volatile LONG*p,LONG n){return __sync_lock_test_and_set(p,n);}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS,size_t,ULONG);
static void MmUnmapIoSpace(void*,size_t);
static ULONG ModelRead(volatile ULONG*);
static void ModelWrite(volatile ULONG*,ULONG);
static void KeStallExecutionProcessor(ULONG);
#define READ_REGISTER_ULONG ModelRead
#define WRITE_REGISTER_ULONG ModelWrite

#endif
