/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Real Windows MDL/S1 and G196->G190 bridge; no driver entry or owner spoof. */
#include "g321_runtime.h"
#include <intrin.h>
#define TAG '123G'
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#define STATIC static
#define UINTN SIZE_T
#include "OpenSha256.h"
#undef CopyMem
#undef ZeroMem
#undef STATIC
#undef UINTN
static NTSTATUS Lock(G321_RUNTIME *r){LARGE_INTEGER t;t.QuadPart=-500000;if(!r||!r->Initialized||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;return KeWaitForSingleObject(&r->Lock,Executive,KernelMode,FALSE,&t);}
static int GoodOwner(const G321_OWNER *o){return o&&o->Enter&&o->Leave&&o->Lease&&o->Stopped&&o->ValidateBacking;}
static NTSTATUS Enter(G321_RUNTIME *r){NTSTATUS st=r->Owner.Enter(r->Owner.Cookie,r->Generation);if(st!=STATUS_SUCCESS)return st;st=r->Owner.Lease(r->Owner.Cookie,r->Generation);if(st!=STATUS_SUCCESS)r->Owner.Leave(r->Owner.Cookie);return st;}
static int Lease(void *p,uint64_t generation){G321_RUNTIME *r=p;return generation!=r->Generation||r->Owner.Lease(r->Owner.Cookie,generation)!=STATUS_SUCCESS;}
static int Stopped(void *p,uint64_t serial,uint64_t generation){G321_RUNTIME *r=p;return serial!=r->StopSerial||Lease(r,generation)||r->Owner.Stopped(r->Owner.Cookie,serial,generation)!=STATUS_SUCCESS;}
static int Read(void *p,uint32_t off,uint32_t *v){G321_RUNTIME *r=p;return Lease(r,r->Generation)||G482CoreRead(r->Io,off,(PULONG)v)!=STATUS_SUCCESS;}
static int Write(void *p,uint32_t off,uint32_t v){G321_RUNTIME *r=p;return Lease(r,r->Generation)||G482CoreWrite(r->Io,off,v)!=STATUS_SUCCESS;}
static int Barrier(void *p,g190_barrier kind){UNREFERENCED_PARAMETER(p);if(kind==G190_ACQUIRE)__dmb(_ARM64_BARRIER_OSHLD);else if(kind==G190_PUBLISH)__dsb(_ARM64_BARRIER_OSHST);else __dsb(_ARM64_BARRIER_OSH);return 0;}
static int Now(void *p,uint64_t *out){ULONGLONG counter;UNREFERENCED_PARAMETER(p);*out=KeQueryInterruptTimePrecise(&counter)/10;return 0;}
static int Wait(void *p,uint32_t us){LARGE_INTEGER t;UNREFERENCED_PARAMETER(p);if(!us||us>1000||KeGetCurrentIrql()!=PASSIVE_LEVEL)return -1;t.QuadPart=-(LONGLONG)us*10;return KeDelayExecutionThread(KernelMode,FALSE,&t)!=STATUS_SUCCESS;}
static int Cancelled(void *p){return InterlockedCompareExchange(&((G321_RUNTIME *)p)->Cancelled,0,0)!=0;}
static int Hash(void *p,const uint8_t *data,size_t n,const uint8_t expected[32]){UCHAR digest[32];ULONG diff=0;UNREFERENCED_PARAMETER(p);if(n>G190_MAX_IMAGE_BYTES)return -1;OpenShaAll(data,n,digest);for(unsigned i=0;i<32;i++)diff|=digest[i]^expected[i];RtlSecureZeroMemory(digest,sizeof(digest));return diff!=0;}
static int Firmware(void *p,uint32_t region,uint32_t offset,uint32_t *v,BOOLEAN write){
 G321_RUNTIME *r=p;if((offset&3)||Lease(r,r->Generation))return -1;
 if(region==1||region==3){if(offset>0x3ffc)return -1;return (write?G482TcmWrite(r->Io,region,offset,*v):G482TcmRead(r->Io,region,offset,(PULONG)v))!=STATUS_SUCCESS;}
 if(region!=2||offset>0xffbffc)return -1;
 uint32_t address=0x4000+offset;
 for(ULONG i=0;i<r->Plan.count;i++){const g321_extent *e=&r->Plan.extent[i];if(e->kind!=G321_CACHE||address<e->iova||address-e->iova>e->bytes-4)continue;
  if(!r->Buffer[i].Mapped||!r->Buffer[i].Cpu)return -1;
  volatile ULONG *at=(volatile ULONG *)((PUCHAR)r->Buffer[i].Cpu+address-e->iova);
  if(write)*at=*v;else *v=*at;return 0;
 }return -1;
}
static int FwWrite(void *p,uint32_t region,uint32_t offset,uint32_t v){return Firmware(p,region,offset,&v,TRUE);}
static int FwRead(void *p,uint32_t region,uint32_t offset,uint32_t *v){return Firmware(p,region,offset,v,FALSE);}
static int Board(void *p){G321_RUNTIME*r=p;return Lease(r,r->Generation)||G482ConfigureCore(r)!=STATUS_SUCCESS;}
VOID G321Initialize(G321_RUNTIME *r){RtlZeroMemory(r,sizeof(*r));KeInitializeMutex(&r->Lock,0);r->Initialized=TRUE;r->LastStatus=STATUS_DEVICE_NOT_READY;}
NTSTATUS G321Prepare(G321_RUNTIME *r,A740_HAL *hal,const ULONG *ids,ULONG n,const G321_OWNER *owner,const g196_inputs *inputs,G482_BINDING *io,const G482_BOARD_INPUT *board,ULONGLONG generation,ULONGLONG serial){
 NTSTATUS st=Lock(r);BOOLEAN entered=FALSE;if(st!=STATUS_SUCCESS)return st;
 if(r->Attempted||r->Closed||!hal||!ids||!n||n>A740_HAL_MAX_ROLE_INPUTS||!GoodOwner(owner)||!inputs||!io||!io->Bound||!board||!generation||!serial){st=STATUS_INVALID_PARAMETER;goto done;}
 if(hal->Report.Phase!=3||hal->Report.Status!=STATUS_SUCCESS||hal->Report.Count>A740_HAL_MAX_INPUTS||hal->ProbeRetained){st=STATUS_DEVICE_NOT_READY;goto done;}
 for(ULONG i=0;i<n;i++){BOOLEAN found=FALSE;for(ULONG j=0;j<i;j++)if(ids[i]==ids[j]){st=STATUS_INVALID_PARAMETER;goto done;}
  for(ULONG j=0;j<hal->Report.Count;j++){const A740_HAL_INPUT *in=&hal->Report.Input[j];if(in->InputId==ids[i]&&in->Attempted&&in->CreateStatus==STATUS_SUCCESS&&in->DeleteStatus==STATUS_SUCCESS&&(in->AvailableDomainTypes&(1u<<DomainTypeTranslateS1)))found=TRUE;}
  if(!found){st=STATUS_NOT_SUPPORTED;goto done;}
 }
 if(io->Pdo!=hal->Pdo){st=STATUS_RESOURCE_TYPE_NOT_FOUND;goto done;}
 if(g196_prepare(inputs,&r->Inputs)!=G196_INPUTS_MATCH){st=STATUS_INVALID_IMAGE_HASH;goto done;}
 r->Generation=generation;r->Io=io;st=G482AdmitBoard(r,board);if(st!=STATUS_SUCCESS)goto done;
 r->ImageCopy=ExAllocatePool2(POOL_FLAG_NON_PAGED,r->Inputs.image.size,TAG);if(!r->ImageCopy){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 RtlCopyMemory(r->ImageCopy,r->Inputs.image.bytes,r->Inputs.image.size);r->Inputs.image.bytes=r->ImageCopy;
 r->CoreStatus=g321_plan_image(&r->Inputs.image,&r->Plan);if(r->CoreStatus!=G190_OK){st=STATUS_INVALID_IMAGE_HASH;goto premap_failure;}
 r->Owner=*owner;r->Generation=generation;r->StopSerial=serial;
 r->InputCount=n;RtlCopyMemory(r->InputIds,ids,n*sizeof(*ids));
 st=Enter(r);if(st!=STATUS_SUCCESS)goto premap_failure;entered=TRUE;
 st=r->Owner.Stopped(r->Owner.Cookie,serial,generation);if(st!=STATUS_SUCCESS)goto premap_failure;
 /* Any HAL partial failure retains domain/handles; do not fabricate cleanup. */
 r->Attempted=TRUE;st=A740HalOpenRole(&r->Role,hal,ids,n,DomainTypeTranslateS1);if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 for(ULONG i=0;i<r->Plan.count;i++){
  g321_extent *e=&r->Plan.extent[i];G321_BUFFER *b=&r->Buffer[i];PHYSICAL_ADDRESS low={0},high,skip={0};high.QuadPart=MAXLONGLONG;
  if(Lease(r,generation)||Cancelled(r)){st=STATUS_CANCELLED;goto done;}
  b->Mdl=MmAllocatePagesForMdlEx(low,high,skip,e->bytes,MmNonCached,MM_ALLOCATE_FULLY_REQUIRED);if(!b->Mdl){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
  if(MmGetMdlByteOffset(b->Mdl)||MmGetMdlByteCount(b->Mdl)!=e->bytes){st=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
  b->Cpu=MmMapLockedPagesSpecifyCache(b->Mdl,KernelMode,MmNonCached,NULL,FALSE,NormalPagePriority|MdlMappingNoExecute);
  if(!b->Cpu){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
  RtlZeroMemory(b->Cpu,e->bytes);
  st=r->Owner.ValidateBacking(r->Owner.Cookie,b->Mdl,b->Cpu,e->iova,e->bytes);if(st!=STATUS_SUCCESS)goto done;
  b->MapAttempted=TRUE;st=A740HalMap(&r->Role,b->Mdl,e->iova,e->bytes,3);
  if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}b->Mapped=TRUE;
 }
 {g190_ops ops={r,Lease,Stopped,Read,Write,Barrier,Now,Wait,Cancelled,Hash,FwWrite,FwRead,Board};
  g190_limits limits={65536,10,5000000,500000,500000,3000000};ULONG i=r->Plan.hfi_index;
  r->CoreStatus=g190_initialize(&r->Core,&ops,&limits,r->Buffer[i].Cpu,G190_HFI_BYTES,r->Plan.extent[i].iova);
  if(r->CoreStatus!=G190_OK){st=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}}
 r->Prepared=TRUE;st=STATUS_SUCCESS;goto done;
premap_failure:
 if(r->ImageCopy){ExFreePoolWithTag(r->ImageCopy,TAG);r->ImageCopy=NULL;}RtlZeroMemory(&r->Inputs,sizeof(r->Inputs));
done:
 if(entered)r->Owner.Leave(r->Owner.Cookie);r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}
NTSTATUS G321Start(G321_RUNTIME *r){
 NTSTATUS st=Lock(r);if(st!=STATUS_SUCCESS)return st;
 if(!r->Prepared||r->MastersMayRun||r->Poisoned||r->Closed){st=STATUS_DEVICE_NOT_READY;goto done;}
 st=Enter(r);if(st!=STATUS_SUCCESS)goto done;
 if(Stopped(r,r->StopSerial,r->Generation)){st=STATUS_INVALID_DEVICE_STATE;r->Owner.Leave(r->Owner.Cookie);goto done;}
 /* Beginning the real backend can release CM3/reset; retain before the call. */
 r->MastersMayRun=TRUE;
 r->CoreStatus=g190_preflight_run(&r->Core,0,&r->Inputs.image,&r->Inputs.policy);
 if(r->CoreStatus==G190_OK){st=G482ColdPreflight(r);if(st!=STATUS_SUCCESS)r->CoreStatus=G190_STATE;}
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_begin_epoch(&r->Core,0,r->StopSerial,r->Generation);
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_load_image(&r->Core,r->Core.epoch,&r->Inputs.image);
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_boot_firmware(&r->Core,r->Core.epoch);
 if(r->CoreStatus==G190_OK){st=G482ConfigureFirmwareReady(r);if(st!=STATUS_SUCCESS)r->CoreStatus=G190_STATE;}
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_start_hfi(&r->Core,r->Core.epoch);
 if(r->CoreStatus==G190_OK)r->CoreStatus=g190_startup(&r->Core,r->Core.epoch,&r->Inputs.policy);
 st=r->CoreStatus==G190_OK?STATUS_SUCCESS:STATUS_DEVICE_NOT_READY;
 r->Owner.Leave(r->Owner.Cookie);
done:r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}
VOID G321Cancel(G321_RUNTIME *r){if(r)InterlockedExchange(&r->Cancelled,1);}
NTSTATUS G321ReleaseStopped(G321_RUNTIME *r,ULONGLONG serial){
 NTSTATUS st=Lock(r);if(st!=STATUS_SUCCESS)return st;BOOLEAN entered=FALSE;
 if(!r->Attempted||r->Closed||r->Poisoned||serial<=r->StopSerial){st=STATUS_DEVICE_BUSY;goto done;}
 st=Enter(r);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 st=r->Owner.Stopped(r->Owner.Cookie,serial,r->Generation);if(st!=STATUS_SUCCESS)goto done;
 for(ULONG i=r->Plan.count;i>0;i--){ULONG j=i-1;if(r->Buffer[j].Mapped){st=A740HalUnmap(&r->Role,r->Plan.extent[j].iova,r->Plan.extent[j].bytes);if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}r->Buffer[j].Mapped=FALSE;}}
 st=A740HalCloseStopped(&r->Role);if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 /* Backing is freed only after ALL unmaps/flushes/detaches/deletes succeeded. */
 for(ULONG i=0;i<r->Plan.count;i++){G321_BUFFER *b=&r->Buffer[i];if(b->Cpu)MmUnmapLockedPages(b->Cpu,b->Mdl);if(b->Mdl){MmFreePagesFromMdl(b->Mdl);ExFreePool(b->Mdl);}RtlZeroMemory(b,sizeof(*b));}
 if(r->ImageCopy)ExFreePoolWithTag(r->ImageCopy,TAG);r->ImageCopy=NULL;r->StopSerial=serial;r->Closed=TRUE;r->Prepared=FALSE;r->MastersMayRun=FALSE;
done:if(entered)r->Owner.Leave(r->Owner.Cookie);r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}
