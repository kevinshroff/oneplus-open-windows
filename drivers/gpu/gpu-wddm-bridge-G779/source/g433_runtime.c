/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Owned Windows GPU MDLs + managed-S1 + actual CP transport. No load hook. */
#include "g433_runtime.h"
#include "g433_sqe_pin.h"
#include <intrin.h>
#define TAG '334G'
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#define STATIC static
#define UINTN SIZE_T
#include "OpenSha256.h"
#undef CopyMem
#undef ZeroMem
#undef STATIC
#undef UINTN
static NTSTATUS Lock(KMUTEX *m){LARGE_INTEGER t;t.QuadPart=-500000;if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;return KeWaitForSingleObject(m,Executive,KernelMode,FALSE,&t);}
static int GmuReady(G433_RUNTIME*r){G321_RUNTIME*g=r->Gmu;return g&&g->Prepared&&g->MastersMayRun&&!g->Poisoned&&!g->Closed&&!g->Cancelled&&g->Generation==r->Generation&&g->LastStatus==STATUS_SUCCESS&&g->CoreStatus==G190_OK&&g->Core.phase==G190_STARTUP_COMPLETE&&g->Core.stage==11&&g->Core.startup_acked==15&&g->Core.reset_released;}
static int Lease(void*p){G433_RUNTIME*r=p;return r->Cancelled||!GmuReady(r)||r->Gmu->Owner.Lease(r->Gmu->Owner.Cookie,r->Generation)!=STATUS_SUCCESS;}
static int GpuLease(void*p){G433_RUNTIME*r=p;ULONG gx=0;
 if(Lease(r)||!r->Power.held||r->Power.released||r->Power.poisoned)return -1;
 return G482CoreRead(r->Gmu->Io,0x14340,&gx)!=STATUS_SUCCESS||(gx&3)!=0;
}
static int Read(void*p,uint32_t off,uint32_t*v){G433_RUNTIME*r=p;return GpuLease(r)||G482GpuRead(r->Gmu->Io,off,(PULONG)v)!=STATUS_SUCCESS;}
static int Write(void*p,uint32_t off,uint32_t v){G433_RUNTIME*r=p;return GpuLease(r)||G482GpuWrite(r->Gmu->Io,off,v)!=STATUS_SUCCESS;}
static int Fence(void*p,uint32_t*v){G433_RUNTIME*r=p;return GpuLease(r)||G482CoreRead(r->Gmu->Io,0x24c4c,(PULONG)v)!=STATUS_SUCCESS;}
static int Publish(void*p,const volatile uint32_t*cpu,size_t n){UNREFERENCED_PARAMETER(cpu);UNREFERENCED_PARAMETER(n);if(Lease(p))return -1;__dsb(_ARM64_BARRIER_OSHST);return 0;}
static int Acquire(void*p,volatile uint32_t*cpu,size_t n){UNREFERENCED_PARAMETER(cpu);UNREFERENCED_PARAMETER(n);if(Lease(p))return -1;__dmb(_ARM64_BARRIER_OSHLD);return 0;}
static int Barrier(void*p){if(Lease(p))return -1;__dsb(_ARM64_BARRIER_OSH);return 0;}
static int Now(void*p,uint64_t*v){ULONGLONG c;UNREFERENCED_PARAMETER(p);*v=KeQueryInterruptTimePrecise(&c)/10;return 0;}
static int Wait(void*p,uint32_t us){LARGE_INTEGER t;if(Lease(p)||!us||us>1000)return -1;t.QuadPart=-(LONGLONG)us*10;return KeDelayExecutionThread(KernelMode,FALSE,&t)!=STATUS_SUCCESS;}
static int Cancelled(void*p){G433_RUNTIME*r=p;return InterlockedCompareExchange(&r->Cancelled,0,0)!=0||r->Gmu->Cancelled;}
static NTSTATUS Enter(G433_RUNTIME*r){NTSTATUS s=r->Gmu->Owner.Enter(r->Gmu->Owner.Cookie,r->Generation);if(s!=STATUS_SUCCESS)return s;if(Lease(r)){r->Gmu->Owner.Leave(r->Gmu->Owner.Cookie);return STATUS_DEVICE_NOT_READY;}return STATUS_SUCCESS;}
VOID G433Initialize(G433_RUNTIME*r){RtlZeroMemory(r,sizeof(*r));KeInitializeMutex(&r->Lock,0);r->Initialized=TRUE;r->LastStatus=STATUS_DEVICE_NOT_READY;}
NTSTATUS G433Prepare(G433_RUNTIME*r,G321_RUNTIME*g,A740_HAL*h,const ULONG*ids,ULONG n,const G433_GPU_OPS*gpu,const UCHAR*fw,SIZE_T bytes,ULONGLONG serial){
 NTSTATUS s;BOOLEAN locked=FALSE,entered=FALSE;UCHAR digest[32];ULONG diff=0;
 if(!r||!r->Initialized)return STATUS_INVALID_PARAMETER;s=Lock(&r->Lock);if(s!=STATUS_SUCCESS)return s;
 if(r->Attempted||r->Closed||!g||!g->Initialized||!h||!ids||!n||n>A740_HAL_MAX_ROLE_INPUTS||!gpu||!gpu->GpuStopped||!gpu->AuthenticateZap||!fw||bytes!=G433_SQE_FILE_BYTES||!serial){s=STATUS_INVALID_PARAMETER;goto done;}
 s=Lock(&g->Lock);if(s!=STATUS_SUCCESS)goto done;locked=TRUE;r->Gmu=g;r->Generation=g->Generation;
 if(!GmuReady(r)||g->Role.Hal!=h||serial<=g->StopSerial||!g->InputCount||g->InputCount>A740_HAL_MAX_ROLE_INPUTS){s=STATUS_DEVICE_NOT_READY;goto done;}
 if(h->Report.Phase!=3||h->Report.Status!=STATUS_SUCCESS||h->Report.Count>A740_HAL_MAX_INPUTS||h->ProbeRetained){s=STATUS_DEVICE_NOT_READY;goto done;}
 for(ULONG i=0;i<n;i++){BOOLEAN found=FALSE;
  for(ULONG j=0;j<h->Report.Count;j++){const A740_HAL_INPUT*in=&h->Report.Input[j];if(in->InputId==ids[i]&&in->Attempted&&in->CreateStatus==STATUS_SUCCESS&&in->DeleteStatus==STATUS_SUCCESS&&(in->AvailableDomainTypes&(1u<<DomainTypeTranslateS1)))found=TRUE;}
  if(!found){s=STATUS_NOT_SUPPORTED;goto done;}
  for(ULONG j=0;j<g->InputCount;j++)if(ids[i]==g->InputIds[j]){s=STATUS_INVALID_PARAMETER;goto done;}for(ULONG j=0;j<i;j++)if(ids[i]==ids[j]){s=STATUS_INVALID_PARAMETER;goto done;}}
 /* Copy FIRST, hash owned bytes, then map. A caller cannot alter SQE after
  * validation. Stock SHA establishes identity, never PAS/ZAP authentication. */
 s=G456ValidateFacts(&gpu->Board,&g->Inputs,r->Generation);if(s!=STATUS_SUCCESS)goto done;
 r->Gpu=*gpu;r->StopSerial=serial;
 r->Layout=(G433_LAYOUT){{0xf0000000,0xf0008000,0xf0010000,0xf0030000},{0x8000,0x1000,0x13000,0x1000}};
 s=Enter(r);if(s!=STATUS_SUCCESS)goto done;entered=TRUE;
 s=gpu->GpuStopped(g->Owner.Cookie,serial,r->Generation);if(s!=STATUS_SUCCESS)goto done;
 r->Attempted=TRUE;s=A740HalOpenRole(&r->Role,h,ids,n,DomainTypeTranslateS1);if(s!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 for(ULONG i=0;i<4;i++){
  G321_BUFFER*b=&r->Buffer[i];PHYSICAL_ADDRESS lo={0},hi,skip={0};hi.QuadPart=MAXLONGLONG;
  if(Lease(r)){s=STATUS_DEVICE_NOT_READY;goto done;}
  b->Mdl=MmAllocatePagesForMdlEx(lo,hi,skip,r->Layout.Bytes[i],MmNonCached,MM_ALLOCATE_FULLY_REQUIRED);if(!b->Mdl){s=STATUS_INSUFFICIENT_RESOURCES;goto done;}
  if(MmGetMdlByteOffset(b->Mdl)||MmGetMdlByteCount(b->Mdl)!=r->Layout.Bytes[i]){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
  b->Cpu=MmMapLockedPagesSpecifyCache(b->Mdl,KernelMode,MmNonCached,NULL,FALSE,NormalPagePriority|MdlMappingNoExecute);if(!b->Cpu){s=STATUS_INSUFFICIENT_RESOURCES;goto done;}
  RtlZeroMemory(b->Cpu,r->Layout.Bytes[i]);
  if(i==2){RtlCopyMemory(b->Cpu,fw,bytes);OpenShaAll(b->Cpu,bytes,digest);for(ULONG k=0;k<32;k++)diff|=digest[k]^G433SqeSha[k];RtlSecureZeroMemory(digest,32);if(diff){s=STATUS_INVALID_IMAGE_HASH;goto done;}RtlMoveMemory(b->Cpu,(PUCHAR)b->Cpu+4,bytes-4);RtlZeroMemory((PUCHAR)b->Cpu+bytes-4,r->Layout.Bytes[i]-(bytes-4));}
  s=g->Owner.ValidateBacking(g->Owner.Cookie,b->Mdl,b->Cpu,r->Layout.Iova[i],r->Layout.Bytes[i]);if(s!=STATUS_SUCCESS)goto done;
  b->MapAttempted=TRUE;s=A740HalMap(&r->Role,b->Mdl,r->Layout.Iova[i],r->Layout.Bytes[i],i==1?3:1);if(s!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}b->Mapped=TRUE;
 }
 r->Prepared=TRUE;s=STATUS_SUCCESS;
done:if(entered)g->Owner.Leave(g->Owner.Cookie);if(locked)KeReleaseMutex(&g->Lock,FALSE);r->LastStatus=s;KeReleaseMutex(&r->Lock,FALSE);return s;
}
NTSTATUS G433Run(G433_RUNTIME*r){
 NTSTATUS s;BOOLEAN locked=FALSE,entered=FALSE;g433_memory m[4];
 if(!r||!r->Initialized)return STATUS_INVALID_PARAMETER;s=Lock(&r->Lock);if(s!=STATUS_SUCCESS)return s;
 if(!r->Prepared||r->RunAttempted||r->MastersMayRun||r->Poisoned||r->Closed){s=STATUS_DEVICE_NOT_READY;goto done;}
 s=Lock(&r->Gmu->Lock);if(s!=STATUS_SUCCESS)goto done;locked=TRUE;
 s=Enter(r);if(s!=STATUS_SUCCESS)goto done;entered=TRUE;
 s=r->Gpu.GpuStopped(r->Gmu->Owner.Cookie,r->StopSerial,r->Generation);if(s!=STATUS_SUCCESS)goto done;
 r->RunAttempted=TRUE;
 /* Actual initial frequency/BW ACK and non-legacy OOB GPU_SET precede GPU
  * register setup. No GPU aperture is read until GX-on is qualified. */
 r->MastersMayRun=TRUE;
 {g190_status ps=g440_gpu_acquire(&r->Power,&r->Gmu->Core,&r->Gmu->Inputs.policy,r->StopSerial);
  if(ps!=G190_OK){s=ps==G190_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_NOT_READY;goto done;}}
 /* Re-prove actual GPU quiescence after the GX transition; equal ring
  * pointers alone are not a cold/reset/DMA/TLB/rundown witness. */
 s=r->Gpu.GpuStopped(r->Gmu->Owner.Cookie,r->StopSerial,r->Generation);if(s!=STATUS_SUCCESS)goto done;
 s=G456ConfigureGpuStopped(r);if(s!=STATUS_SUCCESS)goto done;
 if(Lease(r)){s=STATUS_DEVICE_NOT_READY;goto done;}
 for(ULONG i=0;i<4;i++)m[i]=(g433_memory){r->Buffer[i].Cpu,r->Layout.Iova[i],r->Layout.Bytes[i]};
 {g433_cp_ops o={r,GpuLease,Read,Write,Publish,Acquire,Barrier,Now,Wait,Cancelled,Fence};
  /* Any setup write can have reached a master, even when its status fails. */
  r->MastersMayRun=TRUE;
  g433_status cs=g433_cp_run(&r->Core,&o,m,500000);
  if(cs==G433_OK){
   if(Lease(r)){s=STATUS_DEVICE_NOT_READY;goto done;}
   s=r->Gpu.AuthenticateZap(r->Gmu->Owner.Cookie,r->Generation);if(s!=STATUS_SUCCESS)goto done;
   if(Lease(r)){s=STATUS_DEVICE_NOT_READY;goto done;}
   cs=g433_cp_secure_run(&r->Core,500000);
  }
  s=cs==G433_OK?STATUS_SUCCESS:cs==G433_TIMEOUT?STATUS_IO_TIMEOUT:cs==G433_CANCELLED?STATUS_CANCELLED:STATUS_DEVICE_NOT_READY;
 }
done:if(entered)r->Gmu->Owner.Leave(r->Gmu->Owner.Cookie);if(locked)KeReleaseMutex(&r->Gmu->Lock,FALSE);r->LastStatus=s;KeReleaseMutex(&r->Lock,FALSE);return s;
}
VOID G433Cancel(G433_RUNTIME*r){if(r)InterlockedExchange(&r->Cancelled,1);}
NTSTATUS G433ReleaseStopped(G433_RUNTIME*r,ULONGLONG serial){
 NTSTATUS s;BOOLEAN locked=FALSE,entered=FALSE;
 if(!r||!r->Initialized)return STATUS_INVALID_PARAMETER;s=Lock(&r->Lock);if(s!=STATUS_SUCCESS)return s;
 if(!r->Attempted||r->Closed||r->Poisoned||serial<=r->StopSerial){s=STATUS_DEVICE_BUSY;goto done;}
 s=Lock(&r->Gmu->Lock);if(s!=STATUS_SUCCESS)goto done;locked=TRUE;
 /* Release still requires actual current power owner; cancellation alone
  * neither proves quiescence nor permits mapping/backing destruction. */
 s=r->Gmu->Owner.Enter(r->Gmu->Owner.Cookie,r->Generation);if(s!=STATUS_SUCCESS)goto done;entered=TRUE;
 s=r->Gmu->Owner.Lease(r->Gmu->Owner.Cookie,r->Generation);if(s!=STATUS_SUCCESS)goto done;
 s=r->Gpu.GpuStopped(r->Gmu->Owner.Cookie,serial,r->Generation);if(s!=STATUS_SUCCESS)goto done;
 if(r->Power.attempted&&!r->Power.released){g190_status ps=g440_gpu_clear_stopped(&r->Power,serial);if(ps!=G190_OK){s=STATUS_DEVICE_NOT_READY;goto done;}}
 for(ULONG i=4;i>0;i--){ULONG j=i-1;if(r->Buffer[j].Mapped){s=A740HalUnmap(&r->Role,r->Layout.Iova[j],r->Layout.Bytes[j]);if(s!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}r->Buffer[j].Mapped=FALSE;}}
 s=A740HalCloseStopped(&r->Role);if(s!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 for(ULONG i=0;i<4;i++){G321_BUFFER*b=&r->Buffer[i];if(b->Cpu)MmUnmapLockedPages(b->Cpu,b->Mdl);if(b->Mdl){MmFreePagesFromMdl(b->Mdl);ExFreePool(b->Mdl);}RtlZeroMemory(b,sizeof(*b));}
 r->StopSerial=serial;r->Closed=TRUE;r->Prepared=FALSE;r->MastersMayRun=FALSE;s=STATUS_SUCCESS;
done:if(entered)r->Gmu->Owner.Leave(r->Gmu->Owner.Cookie);if(locked)KeReleaseMutex(&r->Gmu->Lock,FALSE);r->LastStatus=s;KeReleaseMutex(&r->Lock,FALSE);return s;
}

NTSTATUS G433Submit(G433_RUNTIME*r,const g433_ib*ib,SIZE_T count,PULONG fence){
 NTSTATUS s;BOOLEAN locked=FALSE,entered=FALSE;
 if(!r||!r->Initialized||!ib||!count||count>512||!fence)return STATUS_INVALID_PARAMETER;
 s=Lock(&r->Lock);if(s!=STATUS_SUCCESS)return s;
 if(!r->Prepared||!r->RunAttempted||!r->MastersMayRun||r->Poisoned||r->Closed||r->Core.stage!=9){s=STATUS_DEVICE_NOT_READY;goto done;}
 s=Lock(&r->Gmu->Lock);if(s!=STATUS_SUCCESS)goto done;locked=TRUE;
 s=Enter(r);if(s!=STATUS_SUCCESS)goto done;entered=TRUE;
 if(GpuLease(r)){s=STATUS_DEVICE_NOT_READY;goto done;}
 {g433_status cs=g433_cp_submit_run(&r->Core,ib,count,500000);
  s=cs==G433_OK?STATUS_SUCCESS:cs==G433_BUSY?STATUS_DEVICE_BUSY:cs==G433_ARGUMENT?STATUS_INVALID_PARAMETER:cs==G433_TIMEOUT?STATUS_IO_TIMEOUT:cs==G433_CANCELLED?STATUS_CANCELLED:STATUS_DEVICE_NOT_READY;
  if(cs==G433_OK)*fence=r->Core.completed;
  if(r->Core.poisoned)r->Poisoned=TRUE;
 }
done:if(entered)r->Gmu->Owner.Leave(r->Gmu->Owner.Cookie);if(locked)KeReleaseMutex(&r->Gmu->Lock,FALSE);r->LastStatus=s;KeReleaseMutex(&r->Lock,FALSE);return s;
}

NTSTATUS G433SubmitAuthorized(G433_RUNTIME*r,PVOID device,PEPROCESS process,
 const G433_SUBMIT_BO*bo,ULONG nb,const g433_ib*ib,ULONG ni,const G433_SUBMIT_AUTH*auth,PULONG fence){
 NTSTATUS st;BOOLEAN gLocked=FALSE,entered=FALSE,mLocked=FALSE;PVOID token=NULL;ULONG completed=0;
 if(!r||!r->Initialized||!device||!process||process!=PsGetCurrentProcess()||!bo||!nb||nb>4096||!ib||!ni||ni>512||!fence)return STATUS_INVALID_PARAMETER;
 if(!auth||!auth->Begin||!auth->End)return STATUS_DEVICE_NOT_READY;
 st=Lock(&r->Lock);if(st!=STATUS_SUCCESS)return st;
 if(!r->Prepared||!r->RunAttempted||!r->MastersMayRun||r->Poisoned||r->Closed||r->Core.stage!=9||r->Core.poisoned||r->Core.issued!=r->Core.completed){st=STATUS_DEVICE_NOT_READY;goto done;}
 st=Lock(&r->Gmu->Lock);if(st!=STATUS_SUCCESS)goto done;gLocked=TRUE;
 st=Enter(r);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 if(GpuLease(r)||r->Role.Poisoned||!r->Role.Domain||r->Role.Type!=DomainTypeTranslateS1){st=STATUS_DEVICE_NOT_READY;goto done;}
 st=Lock(&r->Role.MapLock);if(st!=STATUS_SUCCESS)goto done;mLocked=TRUE;
 for(ULONG i=0;i<nb;i++){
  A740_HAL_MAPPING*m;BOOLEAN found=FALSE;
  if(!bo[i].Flags||(bo[i].Flags&~3u)||!bo[i].Handle||!bo[i].Mdl||!bo[i].Cpu||!bo[i].Bytes||bo[i].Bytes>0x40000000u||bo[i].Iova>UINT64_MAX-bo[i].Bytes){st=STATUS_INVALID_PARAMETER;goto done;}
  for(ULONG j=0;j<i;j++)if(bo[j].Handle==bo[i].Handle){st=STATUS_INVALID_PARAMETER;goto done;}
  for(m=r->Role.MapHead;m;m=m->Next)if(m->Mdl==bo[i].Mdl&&m->Iova==bo[i].Iova&&m->ActualIova==bo[i].Iova&&m->Bytes==bo[i].Bytes&&(m->Permissions&bo[i].Flags)==bo[i].Flags){found=TRUE;break;}
  if(!found){st=STATUS_INVALID_HANDLE;goto done;}
  st=r->Gmu->Owner.ValidateBacking(r->Gmu->Owner.Cookie,bo[i].Mdl,bo[i].Cpu,bo[i].Iova,bo[i].Bytes);if(st!=STATUS_SUCCESS)goto done;
 }
 for(ULONG i=0;i<ni;i++){
  BOOLEAN found=FALSE;ULONGLONG bytes=(ULONGLONG)ib[i].words*4;
  if(!bytes||ib[i].words>0xfffff||(ib[i].iova&3)){st=STATUS_INVALID_PARAMETER;goto done;}
  for(ULONG j=0;j<nb;j++)if((bo[j].Flags&1)&&ib[i].iova>=bo[j].Iova&&bytes<=bo[j].Bytes&&ib[i].iova-bo[j].Iova<=bo[j].Bytes-bytes){found=TRUE;break;}
  if(!found){st=STATUS_INVALID_HANDLE;goto done;}
 }
 st=auth->Begin(auth->Cookie,device,process,r->Generation,bo,nb,ib,ni,&token);
 if(st!=STATUS_SUCCESS||!token){if(st==STATUS_SUCCESS)st=STATUS_DEVICE_NOT_READY;goto done;}
 if(GpuLease(r)){st=STATUS_DEVICE_NOT_READY;goto done;}
 {g433_status cs=g433_cp_submit_run(&r->Core,ib,ni,500000);
  st=cs==G433_OK?STATUS_SUCCESS:cs==G433_BUSY?STATUS_DEVICE_BUSY:cs==G433_ARGUMENT?STATUS_INVALID_PARAMETER:cs==G433_TIMEOUT?STATUS_IO_TIMEOUT:cs==G433_CANCELLED?STATUS_CANCELLED:STATUS_DEVICE_NOT_READY;
  if(cs==G433_OK){completed=r->Core.completed;*fence=completed;}
  if(r->Core.poisoned)r->Poisoned=TRUE;
 }
 done:if(token)auth->End(auth->Cookie,token,st,completed);
 if(mLocked)KeReleaseMutex(&r->Role.MapLock,FALSE);if(entered)r->Gmu->Owner.Leave(r->Gmu->Owner.Cookie);if(gLocked)KeReleaseMutex(&r->Gmu->Lock,FALSE);
 r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}

NTSTATUS G433MapOwnedBo(G433_RUNTIME*r,PMDL mdl,PVOID cpu,ULONGLONG va,SIZE_T bytes){
 NTSTATUS st;BOOLEAN gLocked=FALSE,entered=FALSE;
 if(!r||!r->Initialized||!mdl||!cpu||!bytes||bytes>0x40000000u||(va&4095)||(bytes&4095)||va>UINT64_MAX-bytes)return STATUS_INVALID_PARAMETER;
 st=Lock(&r->Lock);if(st!=STATUS_SUCCESS)return st;
 if(!r->Prepared||!r->RunAttempted||!r->MastersMayRun||r->Poisoned||r->Closed||r->Core.stage!=9||r->Core.poisoned||r->Core.issued!=r->Core.completed){st=STATUS_DEVICE_NOT_READY;goto done;}
 st=Lock(&r->Gmu->Lock);if(st!=STATUS_SUCCESS)goto done;gLocked=TRUE;
 st=Enter(r);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 if(GpuLease(r)||r->Role.Poisoned||!r->Role.Domain||r->Role.Type!=DomainTypeTranslateS1){st=STATUS_DEVICE_NOT_READY;goto done;}
 st=r->Gmu->Owner.ValidateBacking(r->Gmu->Owner.Cookie,mdl,cpu,va,bytes);if(st!=STATUS_SUCCESS)goto done;
 st=A740HalMap(&r->Role,mdl,va,bytes,3);if(r->Role.Poisoned)r->Poisoned=TRUE;
 done:if(entered)r->Gmu->Owner.Leave(r->Gmu->Owner.Cookie);if(gLocked)KeReleaseMutex(&r->Gmu->Lock,FALSE);r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}
