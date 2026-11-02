/* CPU-only: actual builder/auditor, synthetic MDL-like scattered PAs. */
#include "ArmSmmu4KAudit.h"
#include "gpu_va_layout.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define MASK UINT64_C(0x0000fffffffff000)
static uint64_t pool[5*512];
static const uint64_t root=0x120000;
static int rd(void *c,uint64_t pa,uint64_t *out){
 (void)c;if(pa<root||pa-root>=sizeof(pool)||(pa&7))return -1;
 *out=pool[(pa-root)/8];return 0;
}
static uint64_t walk(uint64_t va){
 uint64_t table=root;
 for(unsigned l=1;l<=3;l++){
  uint64_t d;assert(!rd(NULL,table+((va>>(39-l*9))&511)*8,&d));
  if(!(d&1))return 0;
  assert((d&3)==3);
  if(l==3)return (d&MASK)|(va&4095);
  table=d&MASK;
 }
 assert(0);return 0;
}
int main(void){
 const uint64_t va[4]=OGO_CP_VA_INITIALIZER;
 const unsigned sizes[4]={0x8000,0x1000,0x13000,0x1000};
 assert(va[0]==OGO_CP_VA_BASE&&va[1]==OGO_CP_VA_BASE+0x8000&&va[3]==OGO_CP_VA_BASE+0x30000);
 assert(va[2]==(OGO_GPU_SQE_LOW_IOVA?0x100000:OGO_CP_VA_BASE+0x10000));
 ArmSmmu4KRange r[29];unsigned n=0;
 for(unsigned i=0;i<4;i++)for(unsigned j=0;j<sizes[i];j+=4096){
  r[n]=(ArmSmmu4KRange){va[i]+j,UINT64_C(0x800000000)+n*0x3000,4096,15,0,2};n++;
 }
 assert(n==29);
 unsigned pages=OGO_GPU_SQE_LOW_IOVA?5:3;
 ArmSmmu4KConfig c={39,36,root,29};ArmSmmu4KResult b;
 uint64_t snapshot[5*512];memset(pool,0xa5,sizeof(pool));memcpy(snapshot,pool,sizeof(pool));
 if(OGO_GPU_SQE_LOW_IOVA){
  /* Production OsmiBuildInactive sorts BO pages; raw builder requires sorted input. */
  assert(ArmSmmu4KBuild(&c,r,n,pool,5,&b)!=ArmSmmu4KSuccess&&!memcmp(snapshot,pool,sizeof(pool)));
 }
 for(unsigned i=1;i<n;i++)for(unsigned j=i;j&&r[j].iova<r[j-1].iova;j--){ArmSmmu4KRange t=r[j];r[j]=r[j-1];r[j-1]=t;}
 assert(ArmSmmu4KBuild(&c,r,n,pool,pages-1,&b)!=ArmSmmu4KSuccess&&!memcmp(snapshot,pool,sizeof(pool)));
 assert(ArmSmmu4KBuild(&c,r,n,pool,pages,&b)==ArmSmmu4KSuccess);
 assert(b.table_pages==pages&&b.leaf_pages==29&&b.start_level==1&&!b.upper_region);
 unsigned char visited[5];ArmSmmu4KTableIo io={NULL,rd};
 ArmSmmu4KAuditRegion region={r,n,pages,pages*512,visited,5};ArmSmmu4KTableAuditResult audit;
 assert(ArmSmmu4KAuditTables(&io,&c,&b,&region,root,&audit)==ArmSmmu4KSuccess&&audit.complete&&audit.leaf_pages==29);
 unsigned nonzero=0;
 for(unsigned i=0;i<pages*512;i++)if(pool[i])nonzero++;
 assert(nonzero==29+pages-1); /* All unused entries zero, only owned links/leaves. */
 for(unsigned i=0;i<n;i++){assert(walk(r[i].iova)==r[i].physical);assert(walk(r[i].iova+4095)==r[i].physical+4095);}
 assert(!walk(va[2]-4096)&&!walk(va[2]+0x13000));
 if(OGO_GPU_SQE_LOW_IOVA)assert(!walk(OGO_CP_VA_BASE+0x10000));else assert(!walk(0x100000));
 uint64_t saved=pool[va[0]>>30];pool[va[0]>>30]=0;
 assert(ArmSmmu4KAuditTables(&io,&c,&b,&region,root,&audit)!=ArmSmmu4KSuccess);pool[va[0]>>30]=saved;
 r[0].permissions=3;assert(ArmSmmu4KAuditTables(&io,&c,&b,&region,root,&audit)!=ArmSmmu4KSuccess);
 printf("{\"layout\":%u,\"low_sqe\":%u,\"table_pages\":%u,\"leaf_pages\":29,\"result\":\"pass\"}\n",OGO_GPU_NONSECURE64_VA,OGO_GPU_SQE_LOW_IOVA,pages);
}
