/* Host CPU model; actual builder/auditor, synthetic owned backing. */
#include "ArmSmmu4KAudit.h"
#include "gpu_va_layout.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define MASK UINT64_C(0x0000fffffffff000)
static uint64_t pool[3*512];
static const uint64_t root=0x120000;
static int read_desc(void *cookie,uint64_t pa,uint64_t *out){
 (void)cookie;if(pa<root||pa-root>=sizeof(pool)||(pa&7))return -1;
 *out=pool[(pa-root)/8];return 0;
}
/* Independent lower39 4K walker. No translated/shadow reference graph. */
static uint64_t walk(uint64_t va){
 if(va>=(UINT64_C(1)<<39))return 0;
 uint64_t table=root;
 for(unsigned level=1;level<=3;level++){
  uint64_t d;assert(!read_desc(NULL,table+((va>>(39-level*9))&511)*8,&d));
  if(!(d&1))return 0;
  assert((d&3)==3);
  if(level==3)return (d&MASK)|(va&4095);
  table=d&MASK;
 }
 assert(0);return 0;
}
int main(void){
 const uint64_t va[4]=OGO_CP_VA_INITIALIZER;
 const size_t size[4]={0x8000,0x1000,0x13000,0x1000};
 ArmSmmu4KRange ranges[29];unsigned n=0;
 for(unsigned i=0;i<4;i++)for(size_t j=0;j<size[i];j+=4096){
  /* Noncontiguous >32-bit PAs expose accidental VA/PA truncation or coupling. */
  uint64_t pa=UINT64_C(0x800000000)+n*0x3000;
  ranges[n++]=(ArmSmmu4KRange){va[i]+j,pa,4096,15,0,2};
 }
 assert(n==29);
 ArmSmmu4KConfig c={39,36,root,29};ArmSmmu4KResult built;
 assert(ArmSmmu4KBuild(&c,ranges,n,pool,3,&built)==ArmSmmu4KSuccess);
 assert(built.table_pages==3&&built.leaf_pages==29&&built.start_level==1&&!built.upper_region);
 unsigned char visited[3];ArmSmmu4KTableIo io={NULL,read_desc};
 ArmSmmu4KAuditRegion region={ranges,n,3,3*512,visited,3};ArmSmmu4KTableAuditResult audit;
 assert(ArmSmmu4KAuditTables(&io,&c,&built,&region,root,&audit)==ArmSmmu4KSuccess&&audit.complete&&audit.leaf_pages==29);
 for(unsigned i=0;i<n;i++){
  assert(walk(ranges[i].iova)==ranges[i].physical);
  assert(walk(ranges[i].iova+4095)==ranges[i].physical+4095);
 }
 assert(!walk(va[0]-4096)&&!walk(va[0]+0x9000)&&!walk(va[0]+0x23000)&&!walk(va[0]+0x31000));
#if OGO_GPU_NONSECURE64_VA
 assert(va[0]==UINT64_C(0x4000000000)&&(va[0]>>30)==256);
 assert(!walk(0xf0000000)&&!walk(0xf0008000)&&!walk(0xf0010000)&&!walk(0xf0030000));
 for(unsigned i=0;i<4;i++)assert(!walk((uint32_t)va[i]));
#else
 assert(va[0]==UINT64_C(0xf0000000)&&(va[0]>>30)==3);
 assert(!walk(UINT64_C(0x4000000000)));
#endif
 /* A stripped high root index or modified permission must be caught. */
 uint64_t saved=pool[va[0]>>30];pool[va[0]>>30]=0;
 assert(ArmSmmu4KAuditTables(&io,&c,&built,&region,root,&audit)!=ArmSmmu4KSuccess);
 pool[va[0]>>30]=saved;
 ranges[0].permissions=3;
 assert(ArmSmmu4KAuditTables(&io,&c,&built,&region,root,&audit)!=ArmSmmu4KSuccess);
 ranges[0].permissions=15;
 uint64_t snapshot[3*512];memcpy(snapshot,pool,sizeof(pool));
 ranges[28].iova=UINT64_C(1)<<39;
 assert(ArmSmmu4KBuild(&c,ranges,n,pool,3,&built)!=ArmSmmu4KSuccess&&!memcmp(snapshot,pool,sizeof(pool)));
 ranges[28].iova=va[3];ranges[28].physical=UINT64_C(1)<<36;
 assert(ArmSmmu4KBuild(&c,ranges,n,pool,3,&built)!=ArmSmmu4KSuccess&&!memcmp(snapshot,pool,sizeof(pool)));
 printf("{\"layout\":%u,\"table_pages\":3,\"leaf_pages\":29,\"native_evidence\":false,\"result\":\"pass\"}\n",OGO_GPU_NONSECURE64_VA);
}
