#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "a740_hal.h"
static unsigned allocated, maps, unmaps, flushes, closes, irql;
static int fail_alloc, move_map;
static NTSTATUS map_status,unmap_status,flush_status;
ULONG KeGetCurrentIrql(VOID) {return irql;}
VOID RtlInitUnicodeString(UNICODE_STRING *s,const wchar_t *v) {s->Text=v;}
PVOID MmGetSystemRoutineAddress(UNICODE_STRING *s) {(void)s;return NULL;}
PVOID ExAllocatePool2(ULONGLONG flags,SIZE_T n,ULONG tag) {
 (void)flags;(void)tag;if(fail_alloc)return NULL;allocated++;return calloc(1,n);
}
VOID ExFreePoolWithTag(PVOID p,ULONG tag) {(void)tag;assert(allocated);allocated--;free(p);}
static NTSTATUS Map(PIOMMU_DMA_DOMAIN d,ULONG p,IOMMU_MAP_PHYSICAL_ADDRESS *m,
 ULONGLONG *v,PVOID a,PVOID b,IOMMU_DMA_LOGICAL_ADDRESS *out) {
 (void)d;(void)a;(void)b;assert(p&&m->Mdl.Mdl);maps++;*out=*v+(move_map?PAGE_SIZE:0);return map_status;
}
static NTSTATUS Unmap(PIOMMU_DMA_DOMAIN d,ULONGLONG v,SIZE_T n) {(void)d;(void)v;assert(n);unmaps++;return unmap_status;}
static NTSTATUS Flush(PIOMMU_DMA_DOMAIN d) {(void)d;flushes++;return flush_status;}
static NTSTATUS Delete(PIOMMU_DMA_DOMAIN d) {(void)d;closes++;return STATUS_SUCCESS;}
VOID KeInitializeMutex(KMUTEX *m,ULONG n) {(void)n;assert(!pthread_mutex_init(m,NULL));}
NTSTATUS KeWaitForSingleObject(KMUTEX *m,int a,int b,BOOLEAN c,PVOID t) {(void)a;(void)b;(void)c;(void)t;assert(!pthread_mutex_lock(m));return 0;}
VOID KeReleaseMutex(KMUTEX *m,BOOLEAN b) {(void)b;assert(!pthread_mutex_unlock(m));}
static A740_HAL hal;
static void Role(A740_HAL_ROLE *r) {
 memset(r,0,sizeof(*r));KeInitializeMutex(&r->MapLock,0);r->Hal=&hal;r->Domain=(void*)1;r->Count=r->Attached=1;
}
/* Test-only cleanup after a simulated cold reset. Production has no recovery
 * implementation and must retain poisoned records/backing. */
static void ColdReset(A740_HAL_ROLE *r) {
 assert(!pthread_mutex_destroy(&r->MapLock));
 while(r->MapHead){A740_HAL_MAPPING *n=r->MapHead->Next;ExFreePoolWithTag(r->MapHead,A740_HAL_TAG);r->MapHead=n;}
}
typedef struct {A740_HAL_ROLE *Role;PMDL Mdl;NTSTATUS Status;} RACE;
static void *MapRace(void *arg) {
 RACE *r=arg;r->Status=A740HalMap(r->Role,r->Mdl,0x20000,4096,1);return NULL;
}
int main(void) {
 MDL m={8192,0},one={4096,0};A740_HAL_ROLE r;
 hal.Api.V2.MapLogicalRangeEx=Map;hal.Api.V2.UnmapLogicalRange=Unmap;
 hal.Api.V2.FlushDomain=Flush;hal.Api.V2.DeleteDomain=Delete;
 Role(&r);assert(A740HalMap(&r,&m,0x10000,8192,3)==0);
 assert(r.Mappings==1&&r.MapHead->Mdl==&m&&allocated==1);
 assert(A740HalMap(&r,&one,0x11000,4096,1)==STATUS_CONFLICTING_ADDRESSES);
 assert(A740HalMap(&r,&one,0xf000,4096,1)==0); /* exact adjacency */
 assert(maps==2&&r.Mappings==2);
 assert(A740HalUnmap(&r,0x10000,4096)==STATUS_NOT_FOUND);
 assert(A740HalUnmap(&r,0x12000,4096)==STATUS_NOT_FOUND);
 assert(unmaps==0&&flushes==0&&r.Mappings==2);
 assert(A740HalCloseStopped(&r)==STATUS_INVALID_DEVICE_STATE);
 assert(A740HalUnmap(&r,0x10000,8192)==0);
 assert(A740HalUnmap(&r,0xf000,4096)==0);
 r.Attached=0;r.Count=0;assert(A740HalCloseStopped(&r)==0);
 assert(!allocated&&!r.Hal&&closes==1);assert(!pthread_mutex_destroy(&r.MapLock));
 Role(&r);unsigned before=maps;
 assert(A740HalMap(&r,&one,UINT64_MAX-4095,4096,1)==STATUS_INVALID_PARAMETER);
 assert(A740HalMap(&r,&one,1,4096,1)==STATUS_INVALID_PARAMETER);
 assert(A740HalMap(&r,&one,4096,8192,1)==STATUS_INVALID_PARAMETER);
 assert(A740HalMap(&r,&one,4096,4096,4)==STATUS_INVALID_PARAMETER);
 irql=1;assert(A740HalMap(&r,&one,4096,4096,1)==STATUS_INVALID_PARAMETER);irql=0;
 fail_alloc=1;assert(A740HalMap(&r,&one,4096,4096,1)==STATUS_INSUFFICIENT_RESOURCES);fail_alloc=0;
 assert(maps==before&&!r.Mappings&&!allocated);assert(!pthread_mutex_destroy(&r.MapLock));
 /* Failure or unexpected address must preserve the attempted MDL and poison. */
 for(int mode=0;mode<2;mode++) {
  Role(&r);move_map=mode;map_status=mode?0:STATUS_UNSUCCESSFUL;
  assert(A740HalMap(&r,&one,4096,4096,1)==(mode?STATUS_DEVICE_CONFIGURATION_ERROR:STATUS_UNSUCCESSFUL));
  assert(r.Poisoned&&r.Mappings==1&&r.MapHead->Mdl==&one);
  before=maps;assert(A740HalMap(&r,&one,8192,4096,1)==STATUS_INVALID_PARAMETER);
  assert(maps==before&&A740HalCloseStopped(&r)==STATUS_INVALID_DEVICE_STATE);ColdReset(&r);
 }
 move_map=0;map_status=0;
 /* Neither failed unmap nor failed post-unmap invalidation releases ownership. */
 for(int mode=0;mode<2;mode++) {
  Role(&r);assert(A740HalMap(&r,&one,4096,4096,1)==0);
  unmap_status=mode?0:STATUS_UNSUCCESSFUL;flush_status=mode?STATUS_UNSUCCESSFUL:0;
  unsigned prior_flush=flushes;
  assert(A740HalUnmap(&r,4096,4096)==STATUS_UNSUCCESSFUL);
  assert(r.Poisoned&&r.Mappings==1&&allocated==1);
  assert(flushes==prior_flush+(unsigned)mode);
  assert(A740HalUnmap(&r,4096,4096)==STATUS_INVALID_PARAMETER);ColdReset(&r);
 }
 unmap_status=flush_status=0;Role(&r);
 pthread_t threads[8];RACE races[8];unsigned success=0,conflict=0;
 for(unsigned i=0;i<8;i++){races[i]=(RACE){&r,&one,0};assert(!pthread_create(&threads[i],NULL,MapRace,&races[i]));}
 for(unsigned i=0;i<8;i++){assert(!pthread_join(threads[i],NULL));success+=races[i].Status==0;conflict+=races[i].Status==STATUS_CONFLICTING_ADDRESSES;}
 assert(success==1&&conflict==7&&r.Mappings==1);
 assert(A740HalUnmap(&r,0x20000,4096)==0);assert(!pthread_mutex_destroy(&r.MapLock));
 assert(!allocated);puts("PASS: exact ownership, overlap/partial rejection, failure retention, flush ordering, close guard, concurrent overlap serialization");
}
