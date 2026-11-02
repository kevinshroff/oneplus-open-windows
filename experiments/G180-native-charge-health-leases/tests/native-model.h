/* SPDX-License-Identifier: MIT
 * Explicit WDF/OS/MMIO model for compiling the actual native adapter on macOS.
 * It checks requested framework attributes and supplies their documented lock.
 */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
typedef void VOID,*PVOID,*WDFDRIVER,*WDFWORKITEM,*WDFDEVICE,*WDFTIMER,*WDFQUEUE,*WDFREQUEST,*WDFFILEOBJECT,*PWDFDEVICE_INIT,*PDRIVER_OBJECT;
typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int64_t LONGLONG;typedef size_t SIZE_T,ULONG_PTR;typedef int32_t NTSTATUS;
typedef uint8_t UINT8;typedef uint32_t UINT32;typedef uint64_t UINT64;
typedef struct{LONGLONG QuadPart;}LARGE_INTEGER,PHYSICAL_ADDRESS;
typedef struct{PHYSICAL_ADDRESS BaseAddress;LARGE_INTEGER NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
typedef struct{ULONG dwOSVersionInfoSize,dwBuildNumber;}RTL_OSVERSIONINFOW;
typedef struct{unsigned short Length;const void*Buffer;}UNICODE_STRING,*PUNICODE_STRING;
typedef NTSTATUS DRIVER_INITIALIZE(PDRIVER_OBJECT,PUNICODE_STRING);
typedef VOID EVT_WDF_DRIVER_UNLOAD(WDFDRIVER);
typedef VOID EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL(WDFQUEUE,WDFREQUEST,size_t,size_t,ULONG);
typedef VOID EVT_WDF_DEVICE_FILE_CREATE(WDFDEVICE,WDFREQUEST,WDFFILEOBJECT);
typedef VOID EVT_WDF_TIMER(WDFTIMER);
typedef VOID EVT_WDF_WORKITEM(WDFWORKITEM);
#define C_ASSERT(x) _Static_assert(x,#x)
#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22u
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER ((NTSTATUS)-1)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)-2)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)-3)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)-4)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)-5)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)-6)
#define NT_SUCCESS(x) ((NTSTATUS)(x)>=0)
#define PASSIVE_LEVEL 0
#define ALL_PROCESSOR_GROUPS 0xffff
#define PAGE_READONLY 1
#define PAGE_READWRITE 2
#define PAGE_NOCACHE 4
#define POOL_FLAG_NON_PAGED 1
#define MAXULONGLONG UINT64_MAX
#define TRUE 1
#define FALSE 0
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define RtlCopyMemory memcpy
#define RtlZeroMemory(a,b) memset(a,0,b)
static SIZE_T RtlCompareMemory(const void*a,const void*b,SIZE_T n){const UCHAR*x=a,*y=b;SIZE_T i=0;while(i<n&&x[i]==y[i])i++;return i;}
static unsigned Build=26100,Cpus=8,Irql,FullOS=1,FirmwareMatch=1,MapCount,UnmapCount,FailMap,EntryStep,FailEntry;
static int RangesMissing,MutatePart,Mutated;static uint64_t OverlappingRam;
static _Atomic uint64_t Clock=1000000;
static UCHAR Fdt[65536],Toc[4096],Part[0x60000],Irq[4096];
static UCHAR OriginalPart[0x60000],OriginalToc[4096],OriginalFdt[65536];
static unsigned KeGetCurrentIrql(void){return Irql;}
static ULONG KeQueryActiveProcessorCountEx(unsigned group){assert(group==0xffff);return Cpus;}
static uint64_t KeQueryInterruptTime(void){Clock+=10000;return Clock;}
static LARGE_INTEGER KeQueryPerformanceCounter(void*p){assert(!p);return(LARGE_INTEGER){(LONGLONG)Clock+123};}
static NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*v){v->dwBuildNumber=Build;return 0;}
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG p,ULONG id,void*b,ULONG bytes,ULONG*got){assert(p==0x41435049&&id==0x54445344&&bytes==576);extern const UCHAR ModelDsdt[576];memcpy(b,ModelDsdt,576);if(!FirmwareMatch)((UCHAR*)b)[0]^=1;*got=576;return 0;}
static int WinPE(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(void*p,unsigned flags){assert(!p&&!flags);if(RangesMissing)return NULL;PPHYSICAL_MEMORY_RANGE r=calloc(2,sizeof(*r));assert(r);if(OverlappingRam){r[0].BaseAddress.QuadPart=OverlappingRam;r[0].NumberOfBytes.QuadPart=4096;}return r;}
static void ExFreePool(void*p){free(p);}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS at,SIZE_T n,ULONG protection){
 MapCount++;if(MapCount==FailMap)return NULL;
 if(at.QuadPart==0x81a04000){assert(n==65536&&protection==PAGE_READONLY);return Fdt;}
 if(at.QuadPart==0x81eff000){assert(n==4096&&protection==(PAGE_READONLY|PAGE_NOCACHE));return Toc;}
 if(at.QuadPart==0x81e9f000){assert(n==sizeof(Part)&&protection==(PAGE_READWRITE|PAGE_NOCACHE));return Part;}
 assert(at.QuadPart==0x408000&&n==4096&&protection==(PAGE_READWRITE|PAGE_NOCACHE));return Irq;
}
static void MmUnmapIoSpace(void*p,SIZE_T n){assert((p==Fdt&&n==65536)||(p==Toc&&n==4096)||(p==Part&&n==sizeof(Part))||(p==Irq&&n==4096));UnmapCount++;}
static int EntryOK(void){EntryStep++;return EntryStep!=FailEntry;}
static void*ExAllocatePool2(unsigned flags,size_t bytes,unsigned tag){assert(flags==1&&tag=='56CO');return EntryOK()?calloc(1,bytes):NULL;}
static unsigned Freed;
static void ExFreePoolWithTag(void*p,unsigned tag){assert(tag=='56CO');Freed++;free(p);}
static void KeMemoryBarrier(void);
#define WDF_NO_EVENT_CALLBACK NULL
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define WdfDriverInitNonPnpDriver 1
#define FILE_DEVICE_SECURE_OPEN 0x100
#define WdfDeviceIoBuffered 1
#define WdfExecutionLevelPassive 1
#define WdfSynchronizationScopeDevice 2
#define WdfIoQueueDispatchSequential 3
#define WdfFalse 0
#define WDF_REL_TIMEOUT_IN_MS(x) (-(LONGLONG)(x)*10000)
#define DECLARE_CONST_UNICODE_STRING(n,s) const UNICODE_STRING n={sizeof(s)-sizeof(*(s)),s}
typedef struct{unsigned DriverInitFlags;EVT_WDF_DRIVER_UNLOAD*EvtDriverUnload;}WDF_DRIVER_CONFIG;
typedef struct{void*ParentObject;unsigned ExecutionLevel,SynchronizationScope;}WDF_OBJECT_ATTRIBUTES;
typedef struct{unsigned PowerManaged;EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL*EvtIoDeviceControl;}WDF_IO_QUEUE_CONFIG;
typedef struct{EVT_WDF_DEVICE_FILE_CREATE*Create;void*Close,*Cleanup;}WDF_FILEOBJECT_CONFIG;
typedef struct{unsigned AutomaticSerialization;EVT_WDF_WORKITEM*Callback;}WDF_WORKITEM_CONFIG;
typedef struct{unsigned Period,AutomaticSerialization;EVT_WDF_TIMER*Callback;}WDF_TIMER_CONFIG;
#define WDF_DRIVER_CONFIG_INIT(c,cb) memset(c,0,sizeof(*(c)))
#define WDF_OBJECT_ATTRIBUTES_INIT(a) memset(a,0,sizeof(*(a)))
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(q,d) do{assert(d==3);memset(q,0,sizeof(*(q)));}while(0)
#define WDF_FILEOBJECT_CONFIG_INIT(f,c,x,y) do{(f)->Create=c;(f)->Close=x;(f)->Cleanup=y;}while(0)
#define WDF_WORKITEM_CONFIG_INIT(t,c) do{memset(t,0,sizeof(*(t)));(t)->Callback=c;}while(0)
#define WDF_TIMER_CONFIG_INIT(t,c) do{memset(t,0,sizeof(*(t)));(t)->Callback=c;}while(0)
static NTSTATUS WdfDriverCreate(void*o,void*p,void*a,WDF_DRIVER_CONFIG*c,void**d){assert(o&&p&&!a&&c->DriverInitFlags==1&&c->EvtDriverUnload);*d=(void*)1;return EntryOK()?0:-5;}
static NTSTATUS AuxKlibInitialize(void){return EntryOK()?0:-5;}
static void*WdfControlDeviceInitAllocate(void*d,const UNICODE_STRING*s){assert(d&&(s->Length>0));return EntryOK()?(void*)2:NULL;}
static void WdfDeviceInitSetDeviceType(void*d,unsigned t){assert(d&&t==0x22);}
static void WdfDeviceInitSetCharacteristics(void*d,unsigned c,unsigned b){assert(d&&c==0x100&&b);}
static void WdfDeviceInitSetIoType(void*d,unsigned t){assert(d&&t==1);}
static void WdfDeviceInitSetExclusive(void*d,unsigned b){assert(d&&b);}
static void WdfDeviceInitSetFileObjectConfig(void*d,WDF_FILEOBJECT_CONFIG*f,void*a){assert(d&&f->Create&&!f->Close&&!f->Cleanup&&!a);}
static NTSTATUS WdfDeviceInitAssignName(void*d,const UNICODE_STRING*s){assert(d&&s->Length);return EntryOK()?0:-5;}
static NTSTATUS WdfDeviceCreate(void**i,WDF_OBJECT_ATTRIBUTES*a,void**d){assert(*i&&a->ExecutionLevel==1&&a->SynchronizationScope==2);if(!EntryOK())return-5;*i=NULL;*d=(void*)3;return 0;}
static NTSTATUS WdfDeviceCreateSymbolicLink(void*d,const UNICODE_STRING*s){assert(d==(void*)3&&s->Length);return EntryOK()?0:-5;}
static NTSTATUS WdfIoQueueCreate(void*d,WDF_IO_QUEUE_CONFIG*q,void*a,void*out){assert(d==(void*)3&&!q->PowerManaged&&q->EvtIoDeviceControl&&!a&&!out);return EntryOK()?0:-5;}
static NTSTATUS WdfTimerCreate(WDF_TIMER_CONFIG*t,WDF_OBJECT_ATTRIBUTES*a,void**out){assert(t->Period==0&&t->AutomaticSerialization&&t->Callback&&a->ParentObject==(void*)3&&a->ExecutionLevel==1);if(!EntryOK())return-5;*out=(void*)4;return 0;}
static void WdfDeviceInitFree(void*d){assert(d==(void*)2);}
static void WdfControlFinishInitializing(void*d){assert(d==(void*)3);}
static pthread_mutex_t DeviceMutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int LockHeld;
static void WdfObjectAcquireLock(void*d){assert(d==(void*)3&&!LockHeld);assert(!pthread_mutex_lock(&DeviceMutex));LockHeld=1;}
static void WdfObjectReleaseLock(void*d){assert(d==(void*)3&&LockHeld);LockHeld=0;assert(!pthread_mutex_unlock(&DeviceMutex));}
static unsigned TimerStarts,TimerStops;static int Armed;
static int WdfTimerStart(void*t,LONGLONG when){assert(t==(void*)4&&LockHeld&&(when==-50000||when==-250000));TimerStarts++;Armed=1;return 0;}
static atomic_int StopThread;static pthread_t TimerThread;static int ThreadActive;
static int WdfTimerStop(void*t,int wait){assert(t==(void*)4&&wait&&!LockHeld);TimerStops++;atomic_store(&StopThread,1);if(ThreadActive){assert(!pthread_join(TimerThread,NULL));ThreadActive=0;}Armed=0;return 1;}
static atomic_int WorkFlushEntered;static atomic_int WorkQueued;static pthread_t WorkThread;static int WorkThreadActive;
static unsigned WorkEnqueues,WorkFlushes;static void RunWorker(void);
static NTSTATUS WdfWorkItemCreate(WDF_WORKITEM_CONFIG*c,WDF_OBJECT_ATTRIBUTES*a,void**out){assert(!c->AutomaticSerialization&&c->Callback&&a->ParentObject==(void*)3);if(!EntryOK())return-5;*out=(void*)5;return 0;}
static void WdfWorkItemEnqueue(void*w){assert(w==(void*)5&&LockHeld&&!atomic_exchange(&WorkQueued,1));WorkEnqueues++;}
static void WdfWorkItemFlush(void*w){assert(w==(void*)5&&!LockHeld);WorkFlushes++;atomic_store(&WorkFlushEntered,1);if(WorkThreadActive){assert(!pthread_join(WorkThread,NULL));WorkThreadActive=0;}RunWorker();}
typedef struct{void*Buffer;size_t Capacity;NTSTATUS InputStatus,OutputStatus,Status;ULONG_PTR Bytes;}MODEL_REQUEST;
static NTSTATUS WdfRequestRetrieveInputBuffer(void*r,size_t n,void**p,void*z){MODEL_REQUEST*q=r;assert(n==48&&!z);if(!q->InputStatus)*p=q->Buffer;return q->InputStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(void*r,size_t n,void**p,void*z){MODEL_REQUEST*q=r;assert(!z&&n<=q->Capacity);if(!q->OutputStatus)*p=q->Buffer;return q->OutputStatus;}
static void WdfRequestCompleteWithInformation(void*r,NTSTATUS s,ULONG_PTR bytes){MODEL_REQUEST*q=r;q->Status=s;q->Bytes=bytes;}
static void WdfRequestComplete(void*r,NTSTATUS s){WdfRequestCompleteWithInformation(r,s,0);}
static PUNICODE_STRING WdfFileObjectGetFileName(void*f){return f;}
