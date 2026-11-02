#include "open_smmu_inactive.h"
#include "ogo_gpu_allocation.h"
#include <assert.h>
#include <stdio.h>
static uint64_t expected_high;static unsigned allocs,frees,pool_calls;static int unavailable;static uint64_t pool_pa;static void *pool;static size_t pool_bytes;
int KeGetCurrentIrql(void){return 0;}
void *ExAllocatePool2(unsigned flags,size_t n,unsigned tag){(void)flags;(void)tag;allocs++;return calloc(1,n);}
void ExFreePoolWithTag(void*p,unsigned t){(void)t;if(p){frees++;free(p);}}
void *MmAllocateContiguousMemorySpecifyCache(size_t n,PHYSICAL_ADDRESS low,PHYSICAL_ADDRESS high,PHYSICAL_ADDRESS boundary,int cache){
 assert(low.QuadPart==0&&boundary.QuadPart==0&&cache==MmNonCached);assert((uint64_t)high.QuadPart==expected_high);pool_calls++;
 if(unavailable)return NULL;
 pool=aligned_alloc(4096,n);assert(pool);pool_bytes=n;allocs++;return pool;
}
void MmFreeContiguousMemory(void*p){assert(p==pool);frees++;free(p);pool=NULL;}
PHYSICAL_ADDRESS MmGetPhysicalAddress(void*p){assert(pool&&p>=(void*)pool&&(char*)p<(char*)pool+pool_bytes);return (PHYSICAL_ADDRESS){(int64_t)(pool_pa+(uint64_t)((char*)p-(char*)pool))};}
static void run(uint64_t pfn,uint64_t pa,int missing,NTSTATUS expected){
 MDL m={.MdlFlags=MDL_PAGES_LOCKED,.bytes=4096};m.pfns[0]=pfn;OSMI_INPUT in={&m,0x100000,4096};OSMI_TABLES t;OsmiInitialize(&t);pool_pa=pa;unavailable=missing;unsigned before=pool_calls;
 expected_high=OGO_GPU_ALLOC_HIGH;NTSTATUS st=OsmiBuildInactiveGpu(&t,&in,1);if(st!=expected)fprintf(stderr,"pfn%llx pool%llx missing%d: actual%d expected%d\n",(unsigned long long)pfn,(unsigned long long)pa,missing,st,expected);assert(st==expected);assert(!t.ActivationQualified);
 if(st==STATUS_SUCCESS){assert(t.Config.output_bits==36&&t.Config.input_bits==39);assert(t.PoolBytes==3*4096&&t.Tables.leaf_pages==1);assert(OsmiDestroyInactive(&t)==STATUS_SUCCESS);}
 else if(pfn>=OGO_GPU_ALLOC_LIMIT/4096){assert(pool_calls==before&&t.State==OSMI_NEW);}
 else {assert(t.State==OSMI_CLOSED&&t.Pool==NULL&&t.Ranges==NULL&&t.Visited==NULL);}
 assert(allocs==frees);
}
int main(void){
 /* Last complete pool ends exactly at limit; next-page pool crosses it. */
 run(OGO_GPU_ALLOC_LIMIT/4096-1,0x200000,0,STATUS_SUCCESS);
 run(0x90000,OGO_GPU_ALLOC_LIMIT-3*4096,0,STATUS_SUCCESS);
 run(OGO_GPU_ALLOC_LIMIT/4096,0x200000,0,STATUS_CONFLICTING_ADDRESSES);
 run(UINT64_MAX,0x200000,0,STATUS_CONFLICTING_ADDRESSES);
 run(0x90000,OGO_GPU_ALLOC_LIMIT-2*4096,0,STATUS_CONFLICTING_ADDRESSES);
 run(0x90000,OGO_GPU_ALLOC_LIMIT,0,STATUS_CONFLICTING_ADDRESSES);
 run(0x90000,0x200001,0,STATUS_CONFLICTING_ADDRESSES);
 run(0x90000,0x200000,1,STATUS_INSUFFICIENT_RESOURCES);
#if OGO_GPU_LOW_PHYSICAL
 run(0x100000,0x200000,0,STATUS_CONFLICTING_ADDRESSES);
#else
 run(0x100000,0x200000,0,STATUS_SUCCESS);
#endif
 /* Original GMU/bootstrap call remains 36-bit even with GPU-low selected. */
 MDL m={.MdlFlags=MDL_PAGES_LOCKED,.bytes=4096};m.pfns[0]=0x100000;
 OSMI_INPUT in={&m,0x100000,4096};OSMI_TABLES t;OsmiInitialize(&t);
 expected_high=OSMI_PA_LIMIT-1;pool_pa=0x100100000;unavailable=0;
 assert(OsmiBuildInactive(&t,&in,1)==STATUS_SUCCESS&&t.Config.output_bits==36);
 assert(OsmiDestroyInactive(&t)==STATUS_SUCCESS&&allocs==frees);
 puts("actual CP allocator: 9 boundary cases + unchanged high-PA GMU API passed; publication absent");
}
