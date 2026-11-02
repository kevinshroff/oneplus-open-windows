/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Original fixed GMU memory planner using pinned Open format/VMA facts. */
#include "g321_plan.h"
#include "g191_stock_gmu_profile.h"
static void Copy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
static void Zero(void *d,size_t n){uint8_t *a=d;while(n--)*a++=0;}
#define UINT8 uint8_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN size_t
#define VOID void
#define CONST const
#define STATIC static
#define CopyMem Copy
#define ZeroMem Zero
#include "OpenSha256.h"
#undef UINT8
#undef UINT32
#undef UINT64
#undef UINTN
#undef VOID
#undef CONST
#undef STATIC
#undef CopyMem
#undef ZeroMem
static int Add(g321_plan *p,uint32_t va,uint32_t bytes,g321_extent_kind kind){
 if(!bytes||(va&4095)||(bytes&4095)||p->count==G321_MAX_EXTENTS||va>UINT32_MAX-bytes||p->total_bytes>UINT32_MAX-bytes)return 0;
 for(uint32_t i=0;i<p->count;i++){g321_extent *e=&p->extent[i];if(va<(uint64_t)e->iova+e->bytes&&e->iova<(uint64_t)va+bytes)return 0;}
 p->extent[p->count++]=(g321_extent){va,bytes,kind};p->total_bytes+=bytes;return 1;
}
g190_status g321_plan_image(const g190_image *image,g321_plan *out){
 uint8_t digest[32];AdrenoFirmwareBlock blocks[32];size_t count=0;g321_plan p;uint32_t next=0x60000000;
 if(!image||!out||!image->bytes||image->size!=G191_STOCK_GMU_BYTES||image->expected_blocks!=G191_STOCK_GMU_BLOCKS)return G190_ARGUMENT;
 OpenShaAll(image->bytes,image->size,digest);
 for(unsigned i=0;i<32;i++)if(digest[i]!=G191_STOCK_GMU_SHA256[i]||image->sha256[i]!=digest[i])return G190_FIRMWARE;
 if(g190_plan_image(image,blocks,32,&count)!=G190_OK)return G190_FIRMWARE;
 Zero(&p,sizeof(p));
 for(size_t i=0;i<count;i++){
  const AdrenoFirmwareBlock *b=&blocks[i];if(b->bytes)break;
  uint32_t addr=b->address,n=b->value,type=b->type;
  /* TCM prealloc metadata does not request host allocations. */
  if((addr<0x4000&&n<=0x4000-addr)||(addr>=0x10004000&&addr<0x10008000&&n<=0x10008000-addr))continue;
  if((type!=1&&type!=7)||!n||n>UINT32_MAX-4095)return G190_FIRMWARE;
  uint32_t start=addr&~4095u,span=(uint32_t)(((uint64_t)(addr-start)+n+4095)&~4095ull);
  if(start>=0x4000&&start<0x1000000&&span<=0x1000000-start){if(!Add(&p,start,span,G321_CACHE))return G190_FIRMWARE;}
  else if(start>=0x60000000&&start<0x80000000&&span<=0x80000000-start){if(!Add(&p,start,span,G321_PERSISTENT))return G190_FIRMWARE;if(start+span>next)next=start+span;}
  else return G190_FIRMWARE;
 }
 /* Reserve log then HFI in our exclusive domain after fixed metadata. These
  * selected IOVAs are supplied to the board/core, never derived from CPU PA. */
 if(next>0x80000000-G321_LOG_BYTES-G190_HFI_BYTES)return G190_NO_SPACE;
 p.log_index=p.count;if(!Add(&p,next,G321_LOG_BYTES,G321_LOG))return G190_FIRMWARE;next+=G321_LOG_BYTES;
 p.hfi_index=p.count;if(!Add(&p,next,G190_HFI_BYTES,G321_HFI))return G190_FIRMWARE;
 for(size_t i=0;i<count;i++)if(blocks[i].bytes&&blocks[i].region_identifier==2){
  uint32_t covered=0;for(uint32_t j=0;j<p.count;j++){g321_extent *e=&p.extent[j];if(e->kind==G321_CACHE&&blocks[i].address>=e->iova&&(uint64_t)blocks[i].address+blocks[i].bytes<=(uint64_t)e->iova+e->bytes)covered=1;}
  if(!covered)return G190_FIRMWARE;
 }
 *out=p;return G190_OK;
}
