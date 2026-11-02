"""Reuse G182's explicit WDF/resource models,adding asynchronous work/timer models."""
from pathlib import Path
w=Path(__file__).resolve().parent.parent;s=(w.parent/'platform-owner-G182/tests/driver-model.h').read_text();s=s.replace('#include "resources.h"','#include "resources.h"\n#include "protocol.h"\ntypedef int32_t LONG;typedef uint64_t ULONGLONG;typedef uint32_t *PULONG;typedef UCHAR *PUCHAR;')
# UCHAR is declared later in the original; use the primitive type here.
s=s.replace('typedef UCHAR *PUCHAR;', 'typedef uint8_t *PUCHAR;')
s=s.replace('uint8_t Buffer[112]','uint8_t Buffer[281104]').replace('n==112','n==281104').replace('g->Data1==0x8fa58182','g->Data1==0x8fa58184')
a=s.index('static ULONG DbgPrintEx(');b=s.index('static NTSTATUS WdfIoQueueCreate(',a)
s=s[:a]+'''static ULONG DbgPrintEx(ULONG id,ULONG level,const char*format,...){assert(id==77&&!level&&LockHeld&&strstr(format,"G184 release"));va_list ap;va_start(ap,format);ULONG before=va_arg(ap,ULONG),after=va_arg(ap,ULONG);uint64_t maps=va_arg(ap,uint64_t),unmaps=va_arg(ap,uint64_t);ULONG busy=va_arg(ap,ULONG),queued=va_arg(ap,ULONG),valid=va_arg(ap,ULONG),fault=va_arg(ap,ULONG),uncertain=va_arg(ap,ULONG);va_end(ap);assert(before<=20&&!after&&!LiveMaps&&maps>=unmaps&&!busy&&!queued&&!valid&&fault<=1&&uncertain<=1);return 0;}
'''+s[b:]
s+='''
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
'''
(w/'tests/driver-model.h').write_text(s)
