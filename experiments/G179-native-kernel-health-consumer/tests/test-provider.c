/* Actual provider transport over explicit WDF/clock/timeout models.
 * Frozen native bytes do not qualify native WDF behavior; native run is separate. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef int32_t NTSTATUS;typedef uint32_t ULONG;typedef size_t ULONG_PTR;typedef void*PVOID;
typedef struct{size_t Length;const wchar_t*Buffer;}UNICODE_STRING;
typedef struct Target Target;typedef struct Memory Memory;
typedef Target*WDFIOTARGET;typedef void*WDFDEVICE;typedef Memory*WDFMEMORY;
struct Memory{Target*Parent;uint8_t*Bytes;size_t Size;unsigned References,DeletePending;};
struct Target{unsigned Index,Open,Deleted,Pending,Count;Memory*Buffers[2];};
typedef struct{void*ParentObject;}WDF_OBJECT_ATTRIBUTES;
typedef struct{const UNICODE_STRING*Name;ULONG Access,ShareAccess;}WDF_IO_TARGET_OPEN_PARAMS;
typedef struct{Memory*Memory;}WDF_MEMORY_DESCRIPTOR;
typedef struct{unsigned Flags;int64_t Timeout;}WDF_REQUEST_SEND_OPTIONS;
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER ((NTSTATUS)-1)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)-2)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)-3)
#define STATUS_IO_TIMEOUT ((NTSTATUS)-4)
#define NT_SUCCESS(x) ((NTSTATUS)(x)>=0)
#define PASSIVE_LEVEL 0
#define GENERIC_READ UINT32_C(0x80000000)
#define NonPagedPoolNx 512
#define C_ASSERT(x) _Static_assert(x,#x)
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define DECLARE_CONST_UNICODE_STRING(n,s) const UNICODE_STRING n={sizeof(s)-sizeof(*(s)),s}
#define RtlZeroMemory(p,n) memset(p,0,n)
#define WDF_OBJECT_ATTRIBUTES_INIT(a) memset(a,0,sizeof(*(a)))
#define WDF_IO_TARGET_OPEN_PARAMS_INIT_OPEN_BY_NAME(p,n,a) do{memset(p,0,sizeof(*(p)));(p)->Name=n;(p)->Access=a;}while(0)
#define WDF_MEMORY_DESCRIPTOR_INIT_HANDLE(p,m,o) do{assert(!(o));(p)->Memory=m;}while(0)
#define WDF_REQUEST_SEND_OPTION_TIMEOUT 1
#define WDF_REQUEST_SEND_OPTIONS_INIT(p,f) do{memset(p,0,sizeof(*(p)));(p)->Flags=f;}while(0)
#define WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(p,t) ((p)->Timeout=(t))
#define WDF_REL_TIMEOUT_IN_MS(x) (-(int64_t)(x)*10000)
#include "provider_io.h"
static uint8_t Config[CH_CONFIG_BYTES],Gauge[CH_GAUGE_BYTES];
static unsigned Cases,Calls,FailAt,Irql,NextIndex,LiveTargets,LiveMemory,TimeoutAt,ShortAt,WrongNonce,SlowCleanup;
static uint64_t Clock,Nonce;static Target*Pending;
static uint32_t U32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t U64(const uint8_t*p){return U32(p)|(uint64_t)U32(p+4)<<32;}
static unsigned KeGetCurrentIrql(void){return Irql;}
static uint64_t KeQueryInterruptTime(void){Clock+=10000;return Clock;}
static int Step(void){return++Calls!=FailAt;}
static NTSTATUS WdfIoTargetCreate(WDFDEVICE p,void*a,WDFIOTARGET*out){assert(p==(void*)3&&!a);if(!Step())return-5;Target*t=calloc(1,sizeof(*t));assert(t);t->Index=NextIndex++;*out=t;LiveTargets++;return 0;}
static NTSTATUS WdfIoTargetOpen(Target*t,WDF_IO_TARGET_OPEN_PARAMS*p){assert(t&&!t->Open&&p->Access==GENERIC_READ&&!p->ShareAccess);assert(!wcscmp(p->Name->Buffer,t->Index?L"\\Device\\OpenG160":L"\\Device\\OpenG167"));if(!Step())return-5;t->Open=1;return 0;}
static NTSTATUS WdfMemoryCreate(WDF_OBJECT_ATTRIBUTES*a,unsigned pool,unsigned tag,size_t bytes,Memory**out,void**buffer){Target*t=a->ParentObject;assert(t&&t->Open&&pool==512&&tag=='97HC'&&t->Count<2);if(!Step())return-5;Memory*m=calloc(1,sizeof(*m));assert(m);m->Bytes=malloc(bytes);assert(m->Bytes);memset(m->Bytes,0xa5,bytes);m->Size=bytes;m->Parent=t;t->Buffers[t->Count++]=m;*out=m;*buffer=m->Bytes;LiveMemory++;return 0;}
static NTSTATUS WdfIoTargetSendIoctlSynchronously(Target*t,void*request,ULONG code,WDF_MEMORY_DESCRIPTOR*in,WDF_MEMORY_DESCRIPTOR*out,WDF_REQUEST_SEND_OPTIONS*options,ULONG_PTR*got){
 assert(t&&t->Open&&!request&&options->Flags==1&&options->Timeout==-20000000);
 assert(code==(t->Index?2255304u:2255368u)&&in->Memory==t->Buffers[0]&&out->Memory==t->Buffers[1]);
 Memory*a=in->Memory,*b=out->Memory;assert(a->Size==32&&b->Size==(t->Index?CH_GAUGE_BYTES:CH_CONFIG_BYTES));
 assert(U32(a->Bytes)==32&&U32(a->Bytes+4)==1&&U64(a->Bytes+8)==(t->Index?UINT64_C(0x315147303631474f):UINT64_C(0x314d50373631474f))&&U64(a->Bytes+16)==Nonce&&!U32(a->Bytes+24)&&!U32(a->Bytes+28));
 if(!Step())return-5;
 if(TimeoutAt==t->Index+1){assert(!Pending);t->Pending=1;a->References++;b->References++;Pending=t;return STATUS_IO_TIMEOUT;}
 memcpy(b->Bytes,t->Index?Gauge:Config,b->Size);if(WrongNonce)b->Bytes[80]^=1;
 *got=b->Size-(ShortAt==t->Index+1);return 0;
}
static void WdfIoTargetClose(Target*t){assert(t&&t->Open);t->Open=0;if(SlowCleanup)Clock+=CH_FRESH_100NS;}
static void FreeMemory(Memory*m){assert(!m->References);memset(m->Bytes,0xdd,m->Size);free(m->Bytes);free(m);LiveMemory--;}
static void WdfObjectDelete(Target*t){assert(t&&!t->Open&&!t->Deleted);t->Deleted=1;for(unsigned i=0;i<t->Count;i++){Memory*m=t->Buffers[i];if(m->References)m->DeletePending=1;else{FreeMemory(m);t->Buffers[i]=NULL;}}if(!t->Pending){free(t);LiveTargets--;}}
/* The actual implementation is compiled without replacing a cleanup path. */
#include "provider_io.c"
static void Reset(void){assert(!LiveTargets&&!LiveMemory&&!Pending);Calls=FailAt=Irql=NextIndex=TimeoutAt=ShortAt=WrongNonce=SlowCleanup=0;Clock=U64(Gauge+56)+100000;Nonce=U64(Gauge+80);}
static void CheckClean(const CH_IO_RESULT*r){assert(r->CreatedMask==r->DeletedMask&&r->OpenedMask==r->ClosedMask);if(!Pending)assert(!LiveTargets&&!LiveMemory);Cases++;}
static void FinishLate(void){assert(Pending&&Pending->Deleted&&!Pending->Open&&LiveTargets==1&&LiveMemory==2);Target*t=Pending;assert(U64(t->Buffers[0]->Bytes+16)==Nonce);for(unsigned i=0;i<2;i++){Memory*m=t->Buffers[i];assert(m->References==1&&m->DeletePending);m->References--;FreeMemory(m);}free(t);LiveTargets--;Pending=NULL;assert(!LiveMemory&&!LiveTargets);}
static void Load(const char*p,uint8_t*b,size_t n){FILE*f=fopen(p,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF&&!fclose(f));}
int main(int argc,char**argv){
 assert(argc==4);Load(argv[1],Config,sizeof(Config));Load(argv[2],Gauge,sizeof(Gauge));CH_IO_RESULT r;
 Reset();assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)==0&&r.Valid&&r.Stage==100&&r.HealthCode==0&&r.CreatedMask==3&&r.OpenedMask==3&&r.SentMask==3&&r.ReceivedMask==3&&r.ManagedBuffers==4);assert(r.Health.Nonce==Nonce&&r.End100ns>=r.Validation100ns);CheckClean(&r);unsigned count=Calls;assert(count==10);FILE*save=fopen(argv[3],"wbx");assert(save&&fwrite(&r,1,sizeof(r),save)==sizeof(r)&&!fclose(save));
 for(unsigned at=1;at<=count;at++){Reset();FailAt=at;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)<0&&!r.Valid&&r.FailedStage);CheckClean(&r);}
 for(unsigned i=1;i<=2;i++){
  Reset();TimeoutAt=i;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)==STATUS_IO_TIMEOUT&&!r.Valid);assert(r.SentMask!=r.ReceivedMask);CheckClean(&r);
  volatile uint8_t overwrite[4096];memset((void*)overwrite,0xcc,sizeof(overwrite));FinishLate();
  Reset();ShortAt=i;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)==STATUS_INFO_LENGTH_MISMATCH&&!r.Valid);CheckClean(&r);
 }
 Reset();WrongNonce=1;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)==STATUS_DEVICE_NOT_READY&&r.HealthCode==CH_NONCE&&!r.Valid&&r.ValidationAttempted);CheckClean(&r);
 Reset();SlowCleanup=1;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)==STATUS_DEVICE_NOT_READY&&r.HealthCode==CH_FRESHNESS&&!r.Valid&&r.FailedStage==31);CheckClean(&r);
 Reset();Clock+=CH_FRESH_100NS;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)<0&&r.HealthCode==CH_FRESHNESS&&!r.Valid);CheckClean(&r);
 Reset();assert(ChReadKernelHealth((void*)3,Nonce,Nonce,0,CH_OBSERVE,&r)<0&&r.HealthCode==CH_NONCE);CheckClean(&r);
 Reset();assert(ChReadKernelHealth((void*)3,Nonce,0,U64(Gauge+56),CH_OBSERVE,&r)<0&&r.HealthCode==CH_FRESHNESS);CheckClean(&r);
 Reset();Irql=1;assert(ChReadKernelHealth((void*)3,Nonce,0,0,CH_OBSERVE,&r)==STATUS_INVALID_PARAMETER&&!Calls);CheckClean(&r);
 Reset();assert(ChReadKernelHealth((void*)3,0,0,0,CH_OBSERVE,&r)==STATUS_INVALID_PARAMETER&&!Calls);CheckClean(&r);
 Reset();assert(ChReadKernelHealth(NULL,Nonce,0,0,CH_OBSERVE,&r)==STATUS_INVALID_PARAMETER&&!Calls);CheckClean(&r);
 Reset();assert(ChReadKernelHealth((void*)3,Nonce,0,0,4,&r)==STATUS_INVALID_PARAMETER&&!Calls);CheckClean(&r);
 printf("{\"passed\":true,\"cases\":%u,\"actual_provider_source\":true,\"delayed_timeout_buffers_checked\":2,\"native_operations\":0}\n",Cases);return 0;
}
