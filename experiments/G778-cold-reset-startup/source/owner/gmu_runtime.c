/* Concrete GMU/HFI bridge over the actual published NC/SID5 owner. */
#include "gpu_owner.h"
#include <intrin.h>
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#define STATIC static
#define UINTN SIZE_T
#include "OpenSha256.h"
#undef CopyMem
#undef ZeroMem
#undef STATIC
#undef UINTN
NTSTATUS OgoGmuCurrent(G321_RUNTIME*r){
 if(!r||!r->Owner.Cookie)return STATUS_INVALID_PARAMETER;OGO_CONTEXT*p=r->Owner.Cookie;
 if(p->Gmu!=r||r->Role.Hal||r->Io!=&p->Io||p->Io.Pdo!=p->Pdo||!p->Active||r->Generation!=p->Hold.Generation||p->OperationThread!=PsGetCurrentThread()||InterlockedCompareExchange(&p->Revoked,0,0)||!p->Started||!p->D0||p->Removing||p->StopPending||p->RemovePending||r->Cancelled||r->Closed||r->Poisoned)return STATUS_DEVICE_NOT_READY;
 return OasCurrentRuntime(p->Active);
}
static int Lease(PVOID x,uint64_t generation){G321_RUNTIME*r=x;return generation!=r->Generation||OgoGmuCurrent(r)!=STATUS_SUCCESS;}
static int Stopped(PVOID x,uint64_t serial,uint64_t generation){G321_RUNTIME*r=x;OGO_CONTEXT*p=r->Owner.Cookie;
 /* Valid only before our one actual handoff. Running firmware is never
  * called stopped and no post-run serial can be manufactured by this API. */
 return serial!=p->Hold.Serial||generation!=p->Hold.Generation||!p->Active||p->Active->ColdConsumed||r->Core.reset_released||Lease(r,generation)||CghNativeCheck(&p->Hold)!=STATUS_SUCCESS;
}
static int Read(PVOID x,uint32_t off,uint32_t*v){G321_RUNTIME*r=x;return Lease(r,r->Generation)||G482CoreRead(r->Io,off,(PULONG)v)!=STATUS_SUCCESS||(*v==MAXULONG&&off!=G190_G2H_MASK&&off!=G190_AO_MASK);}
static int Write(PVOID x,uint32_t off,uint32_t v){G321_RUNTIME*r=x;return Lease(r,r->Generation)||G482CoreWrite(r->Io,off,v)!=STATUS_SUCCESS;}
static int Barrier(PVOID x,g190_barrier kind){G321_RUNTIME*r=x;if(Lease(r,r->Generation))return -1;if(kind==G190_ACQUIRE)__dmb(_ARM64_BARRIER_OSHLD);else if(kind==G190_PUBLISH)__dsb(_ARM64_BARRIER_OSHST);else __dsb(_ARM64_BARRIER_OSH);return 0;}
static int Now(PVOID x,uint64_t*out){G321_RUNTIME*r=x;if(Lease(r,r->Generation)||!out)return -1;ULONGLONG counter;*out=KeQueryInterruptTimePrecise(&counter)/10;return 0;}
static int Wait(PVOID x,uint32_t us){G321_RUNTIME*r=x;if(Lease(r,r->Generation)||!us||us>1000)return -1;LARGE_INTEGER t;t.QuadPart=-(LONGLONG)us*10;return KeDelayExecutionThread(KernelMode,FALSE,&t)!=STATUS_SUCCESS;}
static int Cancelled(PVOID x){G321_RUNTIME*r=x;OGO_CONTEXT*p=r->Owner.Cookie;return InterlockedCompareExchange(&p->Revoked,0,0)||InterlockedCompareExchange(&p->Life.Inhibit,0,0);}
static int Hash(PVOID x,const uint8_t*data,size_t n,const uint8_t expected[32]){G321_RUNTIME*r=x;if(Lease(r,r->Generation)||!data||n>G190_MAX_IMAGE_BYTES)return -1;UCHAR sha[32];OpenShaAll(data,n,sha);ULONG diff=0;for(ULONG i=0;i<32;i++)diff|=sha[i]^expected[i];RtlSecureZeroMemory(sha,sizeof(sha));return diff!=0;}
static int Firmware(PVOID x,uint32_t region,uint32_t offset,uint32_t*v,BOOLEAN write){G321_RUNTIME*r=x;if(!v||(offset&3)||Lease(r,r->Generation))return -1;
 if(region==1||region==3){if(offset>0x3ffc)return -1;return (write?G482TcmWrite(r->Io,region,offset,*v):G482TcmRead(r->Io,region,offset,(PULONG)v))!=STATUS_SUCCESS;}
 if(region!=2||offset>0xffbffc)return -1;UINT64 address=0x4000u+offset;
 for(ULONG i=0;i<r->Plan.count;i++){g321_extent*e=&r->Plan.extent[i];if(e->kind!=G321_CACHE||address<e->iova||e->bytes<4||address-e->iova>e->bytes-4)continue;if(!r->Buffer[i].Mapped||!r->Buffer[i].Cpu)return -1;volatile ULONG*at=(volatile ULONG*)((PUCHAR)r->Buffer[i].Cpu+(SIZE_T)(address-e->iova));if(write)*at=*v;else *v=*at;return 0;}return -1;
}
static int FwWrite(PVOID x,uint32_t region,uint32_t offset,uint32_t v){return Firmware(x,region,offset,&v,TRUE);}static int FwRead(PVOID x,uint32_t region,uint32_t offset,uint32_t*v){return Firmware(x,region,offset,v,FALSE);}
static int Board(PVOID x){G321_RUNTIME*r=x;return OgoGmuCurrent(r)!=STATUS_SUCCESS||G482ConfigureCore(r)!=STATUS_SUCCESS;}
NTSTATUS OgoGmuHandoff(G321_RUNTIME*r){NTSTATUS st=OgoGmuCurrent(r);if(st!=STATUS_SUCCESS)return st;OGO_CONTEXT*p=r->Owner.Cookie;r->MastersMayRun=TRUE;return OasHandoffOwnedGbif(p->Active);}
NTSTATUS OgoRunGmu(OGO_CONTEXT*p){
 if(!p||p->Gmu||!p->Active||p->Active->State!=OAS_ACTIVE||!p->Input[5])return STATUS_INVALID_DEVICE_STATE;
 G321_RUNTIME*r=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*r),OGO_TAG);if(!r)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(r,sizeof(*r));p->Gmu=r;KeInitializeMutex(&r->Lock,0);r->Initialized=TRUE;r->Owner.Cookie=p;r->Io=&p->Io;r->Generation=p->Hold.Generation;r->StopSerial=p->Hold.Serial;
 OSMA_TABLE_BINDING*t=p->Active->Tables;r->Plan=t->Plan;r->Inputs=t->Inputs;RtlCopyMemory(r->Buffer,t->Buffer,sizeof(r->Buffer));
 /* Borrow actual mapped backing under the retained active binding; no second
  * allocator/MDL ownership is created. G321Release/Prepare/HAL are not linked. */
 NTSTATUS st=OasEnterFirmwareScope(p->Active);if(st!=STATUS_SUCCESS)return r->LastStatus=st;
 G482_BOARD_INPUT board={r->Generation,0x70201,p->Input[5],20};st=G482AdmitBoard(r,&board);if(st!=STATUS_SUCCESS)goto done;
 ULONG h=r->Plan.hfi_index;if(h>=r->Plan.count||r->Plan.extent[h].bytes!=G190_HFI_BYTES||!r->Buffer[h].Mapped){st=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 g190_ops ops={r,Lease,Stopped,Read,Write,Barrier,Now,Wait,Cancelled,Hash,FwWrite,FwRead,Board};g190_limits limits={65536,10,5000000,500000,500000,3000000};
 r->CoreStatus=g190_initialize(&r->Core,&ops,&limits,r->Buffer[h].Cpu,G190_HFI_BYTES,r->Plan.extent[h].iova);if(r->CoreStatus!=G190_OK)goto backend;
 r->Prepared=TRUE;r->Attempted=TRUE;r->CoreStatus=g190_preflight_run(&r->Core,0,&r->Inputs.image,&r->Inputs.policy);if(r->CoreStatus!=G190_OK)goto backend;
 st=G482ColdPreflight(r);if(st!=STATUS_SUCCESS)goto done;
 r->CoreStatus=g190_begin_epoch(&r->Core,0,r->StopSerial,r->Generation);if(r->CoreStatus==G190_OK)r->CoreStatus=g190_load_image(&r->Core,r->Core.epoch,&r->Inputs.image);
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_boot_firmware(&r->Core,r->Core.epoch);
 if(r->CoreStatus==G190_OK){st=G482ConfigureFirmwareReady(r);if(st!=STATUS_SUCCESS)goto done;}
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_start_hfi(&r->Core,r->Core.epoch);
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_startup(&r->Core,r->Core.epoch,&r->Inputs.policy);
backend:st=r->CoreStatus==G190_OK?STATUS_SUCCESS:r->CoreStatus==G190_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_HARDWARE_ERROR;
done:
 if(st==STATUS_SUCCESS&&(r->Core.phase!=G190_STARTUP_COMPLETE||r->Core.startup_acked!=15||!r->Core.reset_released||!p->Active->ColdConsumed||!p->Hold.BootCommitted))st=STATUS_INVALID_DEVICE_STATE;
 st=OasLeaveFirmwareScope(p->Active,st);r->LastStatus=st;LogPrint("GMU actual status%08x backend%u phase%u stage%u failureStage%u FW%08x HFI%08x resetReleased%u stoppedConsumed%u startupAcked%u; CP/WDDM0\n",st,r->CoreStatus,r->Core.phase,r->Core.stage,r->Core.failure_stage,r->Core.firmware_init_result,r->Core.hfi_status,r->Core.reset_released,p->Active->ColdConsumed,r->Core.startup_acked);return st;
}
