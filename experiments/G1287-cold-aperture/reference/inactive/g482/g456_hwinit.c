/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Concrete source-derived Open A740 register initialization. The existing
 * qualified owner performs actual resource MMIO; no new transport callbacks. */
#include "g433_runtime.h"
#include "g456_tables.h"
#define GMU_DWORD_BASE 0x1a800u
#define GX_STATUS_BYTE 0x14340u
NTSTATUS G456ValidateFacts(const G456_FACTS*f,const g196_preflight*i,ULONGLONG generation){
 if(!f||!i||!generation||f->Generation!=generation||f->SourceProfile!=0x70201u||(f->DdrType!=7&&f->DdrType!=8)||f->CachePolicy!=1||f->SecurePolicy!=1||i->soc_id!=519||i->revision!=2||i->source_sku!=2)return STATUS_NOT_SUPPORTED;
 return STATUS_SUCCESS;
}
static NTSTATUS Record(G433_RUNTIME*r,ULONG bank,ULONG off,ULONG value,ULONG op,NTSTATUS st){
 G456_REPORT*t=&r->Hwinit;if(t->Count>=RTL_NUMBER_OF(t->Access))return STATUS_BUFFER_OVERFLOW;
 t->Access[t->Count++]=(G456_ACCESS){bank,off,value,op,st};return st;
}
static NTSTATUS Lease(G433_RUNTIME*r){
 ULONG value=0;NTSTATUS s;
 if(r->Cancelled||r->Gmu->Cancelled||!r->Power.held||r->Power.released||r->Power.poisoned||r->Gmu->Poisoned||r->Gmu->Closed||r->Gmu->Generation!=r->Generation||r->Gmu->Core.phase!=G190_STARTUP_COMPLETE)return STATUS_DEVICE_NOT_READY;
 s=r->Gmu->Owner.Lease(r->Gmu->Owner.Cookie,r->Generation);if(s!=STATUS_SUCCESS)return s;
 s=G482CoreRead(r->Gmu->Io,GX_STATUS_BYTE,&value);s=Record(r,1,GX_STATUS_BYTE,value,0,s);if(s!=STATUS_SUCCESS)return s;
 return(value&3)?STATUS_DEVICE_POWER_FAILURE:STATUS_SUCCESS;
}
static NTSTATUS Read(G433_RUNTIME*r,ULONG reg,PULONG out){
 NTSTATUS s=Lease(r);ULONG v=0,bank=reg>=GMU_DWORD_BASE,off=(reg-(bank?GMU_DWORD_BASE:0))*4;
 if(s!=STATUS_SUCCESS)return s;
 s=bank?G482CoreRead(r->Gmu->Io,off,&v):G482GpuRead(r->Gmu->Io,off,&v);
 r->Hwinit.Reads++;s=Record(r,bank,off,v,0,s);if(s==STATUS_SUCCESS)*out=v;return s;
}
static NTSTATUS Write(G433_RUNTIME*r,ULONG reg,ULONG value){
 NTSTATUS s=Lease(r);ULONG bank=reg>=GMU_DWORD_BASE,off=(reg-(bank?GMU_DWORD_BASE:0))*4,drop=0;
 if(s!=STATUS_SUCCESS)return s;
 if(!bank){s=G482CoreRead(r->Gmu->Io,0x24c4c,&drop);r->Hwinit.AhbCallStatus=s;r->Hwinit.AhbValue=drop;r->Hwinit.AhbSamples++;if(s!=STATUS_SUCCESS)return s;if(drop)return STATUS_DEVICE_NOT_READY;}
 /* Record attempted writes separately from actual readbacks; even a failed
  * store/status retains the complete runtime until a new stop witness. */
 r->Hwinit.Retained=TRUE;r->Hwinit.Writes++;
 s=bank?G482CoreWrite(r->Gmu->Io,off,value):G482GpuWrite(r->Gmu->Io,off,value);
 s=Record(r,bank,off,value,1,s);if(s!=STATUS_SUCCESS)return s;
 if(!r->Gmu->Core.ops.barrier||r->Gmu->Core.ops.barrier(r->Gmu->Core.ops.cookie,G190_COMPLETE))return STATUS_DEVICE_NOT_READY;
 if(!bank){s=G482CoreRead(r->Gmu->Io,0x24c4c,&drop);r->Hwinit.AhbCallStatus=s;r->Hwinit.AhbValue=drop;r->Hwinit.AhbSamples++;if(s!=STATUS_SUCCESS)return s;if(drop)return STATUS_DEVICE_NOT_READY;}
 return STATUS_SUCCESS;
}
static NTSTATUS Set(G433_RUNTIME*r,ULONG reg,ULONG value){ULONG got=0;NTSTATUS s=Write(r,reg,value);if(s!=STATUS_SUCCESS)return s;s=Read(r,reg,&got);if(s!=STATUS_SUCCESS)return s;return got==value?STATUS_SUCCESS:STATUS_DEVICE_DATA_ERROR;}
static NTSTATUS Rmw(G433_RUNTIME*r,ULONG reg,ULONG mask,ULONG value){ULONG before=0;NTSTATUS s=Read(r,reg,&before);return s==STATUS_SUCCESS?Set(r,reg,(before&~mask)|value):s;}
#define TRY(x) do{s=(x);if(s!=STATUS_SUCCESS)goto done;}while(0)
NTSTATUS G456ConfigureGpuStopped(G433_RUNTIME*r){
 NTSTATUS s=STATUS_INVALID_PARAMETER;ULONG value=0,hbb,lo,hi;G456_REPORT*t;G456_FACTS*f;
 if(!r)return s;t=&r->Hwinit;f=&r->Gpu.Board;
 if(t->Attempted)return STATUS_DEVICE_BUSY;
 /* The outer G433 path has just acquired a successful actual OOB/GX hold
  * after its mandatory real GPUStopped witness, under the same owner lock. */
 s=G456ValidateFacts(f,&r->Gmu->Inputs,r->Generation);if(s!=STATUS_SUCCESS){t->Status=s;return s;}
 t->Attempted=TRUE;t->Stage=1;hbb=f->DdrType==7?14:16;t->HighestBankBit=hbb;lo=(hbb-13)&3;hi=((hbb-13)>>2)&1;
 /* No writes may precede admission of stopped/reset ring state and the
  * explicit no-LLCC/no-protected-range mode. Unknown state is not repaired. */
 /* GBIF halt must already be deasserted by the source-defined pre-GMU
  * boot owner. Never move that earlier store into this later GPU stage. */
 const ULONG zero_regs[]={G456_GBIF_HALT,G456_RBBM_GBIF_HALT,G456_RBBM_INT_0_MASK,0x87cu,0x87du,0x87eu,G456_CP_RB_RPTR,G456_CP_RB_WPTR,0xa00u,G456_GBIF_SCACHE_CNTL0,G456_GBIF_SCACHE_CNTL1,G456_RBBM_SECVID_TSB_CNTL,G456_RBBM_SECVID_TSB_TRUSTED_BASE_LO,G456_RBBM_SECVID_TSB_TRUSTED_BASE_HI,G456_RBBM_SECVID_TSB_TRUSTED_SIZE,0x8e50u};
 for(ULONG i=0;i<RTL_NUMBER_OF(zero_regs);i++){TRY(Read(r,zero_regs[i],&value));if(value){s=STATUS_NOT_SUPPORTED;goto done;}}
 TRY(Read(r,G456_RBBM_STATUS,&value));TRY(Read(r,G456_CP_SQE_CNTL,&value));
 t->Stage=2;
 for(ULONG i=0;i<G456Gbif_COUNT;i++)TRY(Set(r,G456Gbif[i][0],G456Gbif[i][1]));
 TRY(Set(r,G456_UCHE_GBIF_GX_CONFIG,0x10240e0));TRY(Set(r,G456_RBBM_PERFCTR_GPU_BUSY_MASKED,MAXULONG));
 TRY(Set(r,G456_UCHE_TRAP_BASE_LO,0xfffff000));TRY(Set(r,G456_UCHE_TRAP_BASE_HI,0x1ffff));
 TRY(Set(r,G456_UCHE_WRITE_THRU_BASE_LO,0xfffff000));TRY(Set(r,G456_UCHE_WRITE_THRU_BASE_HI,0x1ffff));
 TRY(Set(r,G456_UCHE_GMEM_RANGE_MIN_LO,0x1000000));TRY(Set(r,G456_UCHE_GMEM_RANGE_MIN_HI,0));
 TRY(Set(r,G456_UCHE_GMEM_RANGE_MAX_LO,0x12fffff));TRY(Set(r,G456_UCHE_GMEM_RANGE_MAX_HI,0));
 TRY(Set(r,G456_UCHE_CACHE_WAYS,0x800000));TRY(Set(r,G456_UCHE_CMDQ_CONFIG,0x6690e));
 /* Dynamic perfcounter list empty; no PERFCTR_CNTL enable. This path
  * requests no IFPC/LPAC/preemption/BCL feature; CP explicitly disables DMS.
  * It does not infer firmware defaults or implement a production scheduler. */
 TRY(Set(r,G456_GMU_CX_GMU_POWER_COUNTER_SELECT_1,4));
 TRY(Set(r,G456_RB_NC_MODE_CNTL,(1u<<11)|(hi<<10)|(1u<<4)|(lo<<1)));
 TRY(Set(r,G456_TPL1_NC_MODE_CNTL,(hi<<4)|(lo<<1)));
 TRY(Set(r,G456_SP_NC_MODE_CNTL,(hi<<10)|(2u<<4)|(lo<<1)));
 TRY(Set(r,G456_GRAS_NC_MODE_CNTL,(hbb-13)<<5));TRY(Set(r,G456_UCHE_MODE_CNTL,lo<<21));
 TRY(Set(r,G456_RBBM_INTERFACE_HANG_INT_CNTL,0x40cfffff));TRY(Set(r,G456_UCHE_CLIENT_PF,0x81));
 TRY(Rmw(r,G456_RB_CMP_DBG_ECO_CNTL,0x800,0x800));
 TRY(Set(r,G456_GPU_GMU_AO_GPU_CX_BUSY_MASK,0xff000000));
 TRY(Rmw(r,G456_GMU_CX_GMU_POWER_COUNTER_SELECT_0,0xff,0x20));TRY(Set(r,G456_GMU_CX_GMU_POWER_COUNTER_ENABLE,1));
 t->Stage=3;TRY(Set(r,G456_CP_PROTECT_CNTL,0xb));
 for(ULONG i=0;i<G456Protect_COUNT;i++)TRY(Set(r,G456Protect[i][0],G456Protect[i][1]));
 /* Source LLCC helpers are no-ops with no owned/enabled slices; preflight
  * required zero GPU SCIDs. No shared-cache activation or secure-range store. */
 TRY(Set(r,G456_CP_APRIV_CNTL,0x6f));TRY(Set(r,G456_CP_BV_APRIV_CNTL,0xf));TRY(Set(r,G456_CP_LPAC_APRIV_CNTL,0xf));
 TRY(Set(r,G456_CP_CHICKEN_DBG,1));TRY(Set(r,G456_CP_BV_CHICKEN_DBG,1));TRY(Set(r,G456_CP_LPAC_CHICKEN_DBG,1));
 /* Preserve the admitted zero TSB policy; never transplant Android secure
  * IOVA ranges into the Windows HAL-owned nonsecure GPU domain. */
 t->Stage=4;for(ULONG i=0;i<G456AoHwcg_COUNT;i++)TRY(Set(r,G456AoHwcg[i][0],G456AoHwcg[i][1]));
 TRY(Read(r,G456_RBBM_CLOCK_CNTL,&value));
 t->Stage=5;if(value==0x8aa8aa82)t->HwcgSkipped=1;
 else{for(ULONG i=0;i<G456Hwcg_COUNT;i++)TRY(Set(r,G456Hwcg[i][0],G456Hwcg[i][1]));TRY(Set(r,G456_RBBM_CLOCK_CNTL,0x8aa8aa82));}
 /* Open snapshots its IFPC/preemption lists after this point; G433 core
  * consumes the exact derived Open lists before releasing CP. */
 t->Stage=6;TRY(Read(r,G456_RBBM_CLOCK_CNTL,&value));if(value!=0x8aa8aa82){s=STATUS_DEVICE_DATA_ERROR;goto done;}
 TRY(Read(r,G456_CP_RB_RPTR,&value));if(value){s=STATUS_DEVICE_BUSY;goto done;}
 t->Complete=TRUE;t->Stage=7;s=STATUS_SUCCESS;
done:t->Status=s;return s;
}
