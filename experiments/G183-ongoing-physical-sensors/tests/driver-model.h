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
#include "protocol.h"
typedef int32_t LONG;typedef uint64_t ULONGLONG;typedef uint32_t *PULONG;typedef uint8_t *PUCHAR;
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
typedef struct{uint8_t Buffer[281104];size_t Capacity,Bytes;NTSTATUS InputStatus,OutputStatus,Status;}MODEL_REQUEST,*WDFREQUEST;
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
static ULONG DbgPrintEx(ULONG id,ULONG level,const char*format,...){assert(id==77&&!level&&LockHeld&&strstr(format,"G183 release"));va_list ap;va_start(ap,format);ULONG before=va_arg(ap,ULONG),after=va_arg(ap,ULONG);uint64_t maps=va_arg(ap,uint64_t),unmaps=va_arg(ap,uint64_t);ULONG busy=va_arg(ap,ULONG),queued=va_arg(ap,ULONG),valid=va_arg(ap,ULONG),fault=va_arg(ap,ULONG),uncertain=va_arg(ap,ULONG);va_end(ap);assert(before<=20&&!after&&!LiveMaps&&maps>=unmaps&&!busy&&!queued&&!valid&&fault<=1&&uncertain<=1);return 0;}
static NTSTATUS WdfIoQueueCreate(WDFDEVICE d,WDF_IO_QUEUE_CONFIG*q,void*a,void*out){assert(d==Device&&!q->PowerManaged&&q->EvtIoDeviceControl&&!a&&!out);return EntryOK()?0:-4;}
static NTSTATUS WdfDeviceCreateDeviceInterface(WDFDEVICE d,const GUID*g,void*s){assert(d==Device&&g->Data1==0x8fa58183&&!s);return EntryOK()?0:-4;}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){assert(q==Device);return q;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,void**b,void*z){assert(n==32&&!z);if(!r->InputStatus)*b=r->Buffer;return r->InputStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,void**b,void*z){assert(n==281104&&n<=r->Capacity&&!z);if(!r->OutputStatus)*b=r->Buffer;return r->OutputStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,size_t n){r->Status=s;r->Bytes=n;}
static void WdfRequestComplete(WDFREQUEST r,NTSTATUS s){WdfRequestCompleteWithInformation(r,s,0);}
static PUNICODE_STRING WdfFileObjectGetFileName(WDFFILEOBJECT f){return f;}

#define FALSE 0
#define KernelMode 0
#define NonPagedPoolNx 0
#define WDF_REL_TIMEOUT_IN_MS(ms) (-(int64_t)(ms)*10000)
#define RtlZeroMemory(p,n) memset(p,0,n)
typedef void*WDFMEMORY;
typedef struct MODEL_WORK*WDFWORKITEM;
typedef struct MODEL_TIMER*WDFTIMER;
typedef VOID EVT_WDF_WORKITEM(WDFWORKITEM);
typedef VOID EVT_WDF_TIMER(WDFTIMER);
typedef struct{EVT_WDF_WORKITEM*Callback;unsigned AutomaticSerialization;}WDF_WORKITEM_CONFIG;
typedef struct{EVT_WDF_TIMER*Callback;unsigned AutomaticSerialization;}WDF_TIMER_CONFIG;
#define WDF_WORKITEM_CONFIG_INIT(c,f) do{(c)->Callback=f;(c)->AutomaticSerialization=1;}while(0)
#define WDF_TIMER_CONFIG_INIT(c,f) do{(c)->Callback=f;(c)->AutomaticSerialization=1;}while(0)
struct MODEL_WORK{WDFDEVICE Parent;EVT_WDF_WORKITEM*Callback;unsigned Queued,Running;pthread_mutex_t Mutex;pthread_cond_t Cond;};
struct MODEL_TIMER{WDFDEVICE Parent;EVT_WDF_TIMER*Callback;unsigned Armed,Starts,Stops;};
static WDFWORKITEM Work;static WDFTIMER Timer;static void*Memory[2];static unsigned MemoryCount,WinPEGood=1;
static int WinPE(void){return WinPEGood;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){return __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST);}
static LONG InterlockedCompareExchange(volatile LONG*p,LONG value,LONG compare){__atomic_compare_exchange_n(p,&compare,value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return compare;}
static LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*f){if(f)f->QuadPart=1000000;LARGE_INTEGER n={(int64_t)KeQueryInterruptTime()/10};return n;}
static void KeStallExecutionProcessor(ULONG us){assert(us==1||us==20);atomic_fetch_add(&Clock,(uint64_t)us*10);}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-200000);atomic_fetch_add(&Clock,200000);}
static ULONG READ_REGISTER_ULONG(PULONG p){(void)p;assert(!"Register access outside modeled sensor boundary");return 0;}
static void WRITE_REGISTER_ULONG(PULONG p,ULONG v){(void)p;(void)v;assert(!"Register access outside modeled sensor boundary");}
static NTSTATUS WdfMemoryCreate(WDF_OBJECT_ATTRIBUTES*a,int pool,ULONG tag,size_t n,WDFMEMORY*h,void**b){assert(a->ParentObject==Device&&!pool&&tag&&n==sizeof(S183_RESULT)&&MemoryCount<2);if(!EntryOK())return-4;Memory[MemoryCount]=malloc(n);assert(Memory[MemoryCount]);memset(Memory[MemoryCount],0xdd,n);*h=*b=Memory[MemoryCount++];return 0;}
static NTSTATUS WdfWorkItemCreate(WDF_WORKITEM_CONFIG*c,WDF_OBJECT_ATTRIBUTES*a,WDFWORKITEM*out){assert(c->Callback&&!c->AutomaticSerialization&&a->ParentObject==Device&&!Work);if(!EntryOK())return-4;Work=calloc(1,sizeof(*Work));assert(Work);Work->Parent=Device;Work->Callback=c->Callback;assert(!pthread_mutex_init(&Work->Mutex,NULL)&&!pthread_cond_init(&Work->Cond,NULL));*out=Work;return 0;}
static NTSTATUS WdfTimerCreate(WDF_TIMER_CONFIG*c,WDF_OBJECT_ATTRIBUTES*a,WDFTIMER*out){assert(c->Callback&&!c->AutomaticSerialization&&a->ParentObject==Device&&!Timer);if(!EntryOK())return-4;Timer=calloc(1,sizeof(*Timer));assert(Timer);Timer->Parent=Device;Timer->Callback=c->Callback;*out=Timer;return 0;}
static WDFDEVICE WdfTimerGetParentObject(WDFTIMER t){return t->Parent;}
static WDFDEVICE WdfWorkItemGetParentObject(WDFWORKITEM i){return i->Parent;}
static int WdfTimerStart(WDFTIMER t,int64_t due){assert(LockHeld&&t==Timer&&due==-10000000);t->Armed=1;t->Starts++;return 0;}
static int WdfTimerStop(WDFTIMER t,int wait){assert(!LockHeld&&t==Timer&&wait);t->Armed=0;t->Stops++;return 0;}
static void WdfWorkItemEnqueue(WDFWORKITEM i){assert(LockHeld&&i==Work);assert(!pthread_mutex_lock(&i->Mutex));assert(!i->Queued);i->Queued=1;assert(!pthread_mutex_unlock(&i->Mutex));}
static void RunWork(void){assert(!LockHeld);assert(!pthread_mutex_lock(&Work->Mutex));assert(Work->Queued&&!Work->Running);Work->Queued=0;Work->Running=1;assert(!pthread_mutex_unlock(&Work->Mutex));Work->Callback(Work);assert(!pthread_mutex_lock(&Work->Mutex));Work->Running=0;pthread_cond_broadcast(&Work->Cond);assert(!pthread_mutex_unlock(&Work->Mutex));}
static void WdfWorkItemFlush(WDFWORKITEM i){assert(!LockHeld&&i==Work);assert(!pthread_mutex_lock(&i->Mutex));while(i->Running)pthread_cond_wait(&i->Cond,&i->Mutex);unsigned queued=i->Queued;assert(!pthread_mutex_unlock(&i->Mutex));if(queued)RunWork();}
static S183_RESULT Fixture;
static _Atomic unsigned CaptureCalls;
static unsigned CaptureMode,BlockCapture,CaptureEntered,ReleaseCapture;
static pthread_mutex_t CaptureMutex=PTHREAD_MUTEX_INITIALIZER;static pthread_cond_t CaptureCond=PTHREAD_COND_INITIALIZER;
void S183Capture(const S183_IO*io,uint64_t epoch,uint64_t sequence,S183_RESULT*r){
 atomic_fetch_add(&CaptureCalls,1);assert(!LockHeld&&io->Context&&epoch&&sequence);
 assert(!pthread_mutex_lock(&CaptureMutex));CaptureEntered=1;pthread_cond_broadcast(&CaptureCond);while(BlockCapture&&!ReleaseCapture)pthread_cond_wait(&CaptureCond,&CaptureMutex);assert(!pthread_mutex_unlock(&CaptureMutex));
 memcpy(r,&Fixture,sizeof(*r));r->Epoch=epoch;r->Sequence=sequence;r->Begin100ns=KeQueryInterruptTime();r->ConfigEnd100ns=KeQueryInterruptTime();r->GaugeEnd100ns=KeQueryInterruptTime();r->End100ns=KeQueryInterruptTime();
 if(CaptureMode==1){r->Code=S183_CANCELLED;r->CancelledClean=1;}
 if(CaptureMode==2){r->Code=S183_GAUGE;r->Uncertain=1;}
}
