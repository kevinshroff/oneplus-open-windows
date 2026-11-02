
static G58HID_CONTEXT C;static G58_TRIAL KernelResult,Response;
static volatile LONG HWCalls,HWEntered,AllowFinish,HoldThread,Scenario;
static ULONG Build=26100,Processors=8,Irql,FirmwareMatch=1;
static unsigned Submits,Deletes,Frees,Starts,HandlesCreated,HandlesClosed,Joins,Cases,FailCreate,FailSubmit,HWQueries;
static NTSTATUS StartReturn,AsyncStatus;static uint8_t Reports[128][64];
static void Nap(void){struct timespec ts={0,1000000};nanosleep(&ts,NULL);}
static G58HID_CONTEXT*G58HIDContext(WDFDEVICE d){assert(d==(void*)1);return&C;}
static WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q){assert(q==(void*)2);return(void*)1;}
static WDFDEVICE WdfFileObjectGetDevice(WDFFILEOBJECT f){assert(f==(void*)5||f==(void*)6);return(void*)1;}
static WDFFILEOBJECT WdfRequestGetFileObject(WDFREQUEST r){return r->File;}
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==16);if(!r->InStatus)*p=r->In;return r->InStatus;}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST r,size_t n,PVOID*p,size_t*z){(void)z;assert(n==160||n==96||n==80||n==288||n==1728||n==959896);if(!r->OutStatus)*p=r->Out;return r->OutStatus;}
static void WdfRequestCompleteWithInformation(WDFREQUEST r,NTSTATUS s,ULONG_PTR n){r->Completed=s;r->Information=n;}
static ULONG KeQueryActiveProcessorCountEx(ULONG g){assert(g==ALL_PROCESSOR_GROUPS);return Processors;}
static ULONG KeGetCurrentIrql(void){return Irql;}
static NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*v){v->dwBuildNumber=Build;return 0;}
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG a,ULONG b,void*out,ULONG size,ULONG*n){assert(a==0x41435049&&b==0x54445344&&size==sizeof(G58HIDExpectedDsdt));*n=size;memcpy(out,G58HIDExpectedDsdt,size);if(!FirmwareMatch)((uint8_t*)out)[0]^=1;return 0;}
static NTSTATUS KeWaitForSingleObject(void*p,int r,int m,int a,void*t){assert(r==Executive&&m==KernelMode&&!a&&!t);assert(!pthread_mutex_lock(p));return 0;}
static int KeReleaseMutex(KMUTEX*p,int wait){assert(!wait&&!pthread_mutex_unlock(p));return 0;}
static void ExFreePoolWithTag(void*p,ULONG tag){assert(p==&KernelResult&&tag==(ULONG)'85GO');Frees++;}
static NTSTATUS VhfReadReportSubmit(VHFHANDLE h,PHID_XFER_PACKET p){assert(h==(void*)3&&p&&p->reportId==1&&p->reportBufferLen==64&&p->reportBuffer[0]==1&&p->reportBuffer[63]>=1&&p->reportBuffer[63]<=10);assert(Submits<128);memcpy(Reports[Submits++],p->reportBuffer,64);return Submits==FailSubmit?STATUS_DEVICE_NOT_READY:0;}
static NTSTATUS VhfStart(VHFHANDLE h){assert(h==(void*)3);Starts++;return StartReturn;}
static void VhfDelete(VHFHANDLE h,int wait){assert(h==(void*)3&&wait&&!C.Thread);Deletes++;}
static NTSTATUS VhfAsyncOperationComplete(VHFOPERATIONHANDLE h,NTSTATUS status){assert(h==(void*)4);AsyncStatus=status;return 0;}
uint64_t G58HardwareTimeUs(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*1000000+(uint64_t)t.tv_nsec/1000;}
void G58HardwareStatus(G58_STATUS*out){memset(out,0,sizeof(*out));out->Size=80;out->Version=1;out->Magic=G58_MAGIC;HWQueries++;}
NTSTATUS G58HardwareSnapshot(G58_SNAPSHOT*out,const G58_STREAM_IO*io){assert(io&&io->Available(io->Context));memset(out,0,sizeof(*out));HWQueries++;return 0;}
void G58HardwarePmic(G58_PMIC*out,const G58_STREAM_IO*io){assert(io&&io->Available(io->Context));memset(out,0,sizeof(*out));HWQueries++;}
static void SendPoint(const G58_STREAM_IO*io,unsigned index){assert(index<4);if(!io->Stage(io->Context,G58TESTReplayRaw[index],26,10000+index*10000))return;if(!io->Publish(io->Context,G58TESTReplayRaw[index],26))return;}
void G58HardwareTrial(G58_TRIAL*out,const G58_STREAM_IO*io){
 assert(out==C.Result&&out!=&Response&&io&&io->Stage&&io->Publish&&io->StopRequested&&io->Available);InterlockedIncrement(&HWCalls);memset(out,0,sizeof(*out));out->Attempt=1;
 out->FixedRegistersUnchanged=out->Trial.SafeRelease=out->Trial.Power.Restored=out->Trial.Spi.Restored=out->Trial.Spi.Engine.Restored=out->Trial.Touch.Restored=1;out->Trial.Touch.Poll.Limit=100;
 if(__atomic_load_n(&Scenario,__ATOMIC_SEQ_CST)==0){for(unsigned i=0;i<4;i++)SendPoint(io,i);out->Trial.Touch.Poll.Cycles=100;InterlockedExchange(&HWEntered,1);return;}
 SendPoint(io,0);out->Trial.Touch.Stage=8;InterlockedExchange(&HWEntered,1);
 for(unsigned spin=0;spin<5000;spin++){
  if(!io->Available(io->Context)){out->Trial.Power.Code=6;out->Trial.Power.Restored=0;out->Trial.Power.RestoreError=7;out->Trial.SafeRelease=0;return;}
  if(io->StopRequested(io->Context)){out->Trial.Touch.Code=G58_TOUCH_CANCELLED;out->Trial.Power.Code=6;out->Trial.Touch.Poll.Code=G58_POLL_CANCELLED;return;}
  if(__atomic_load_n(&AllowFinish,__ATOMIC_SEQ_CST)){out->Trial.Touch.Poll.Cycles=100;return;}Nap();
 }assert(!"worker was not stopped or released");
}
typedef struct{pthread_t Id;void(*Run)(void*);void*Context;int Joined;}SimThread;
static void*ThreadStart(void*x){SimThread*t=x;while(__atomic_load_n(&HoldThread,__ATOMIC_SEQ_CST)&&!__atomic_load_n(&C.StopReason,__ATOMIC_SEQ_CST))Nap();t->Run(t->Context);return NULL;}
static NTSTATUS PsCreateSystemThread(HANDLE*out,ULONG access,OBJECT_ATTRIBUTES*attrs,void*process,void*id,void(*run)(void*),void*ctx){assert(access==SYNCHRONIZE&&attrs->Flags==OBJ_KERNEL_HANDLE&&!process&&!id&&ctx==&C);if(FailCreate){*out=NULL;return STATUS_INSUFFICIENT_RESOURCES;}SimThread*t=calloc(1,sizeof(*t));assert(t);t->Run=run;t->Context=ctx;assert(!pthread_create(&t->Id,NULL,ThreadStart,t));*out=t;HandlesCreated++;return 0;}
static NTSTATUS ZwWaitForSingleObject(HANDLE h,int alert,void*timeout){SimThread*t=h;assert(t&&!alert&&!timeout&&!t->Joined&&!pthread_equal(pthread_self(),t->Id));assert(!pthread_join(t->Id,NULL));t->Joined=1;Joins++;return 0;}
static NTSTATUS ZwClose(HANDLE h){SimThread*t=h;assert(t&&t->Joined);free(t);HandlesClosed++;return 0;}
__attribute__((noreturn))static void PsTerminateSystemThread(NTSTATUS s){assert(!s);pthread_exit(NULL);}
