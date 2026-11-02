/* SPDX-License-Identifier: MIT. No platform calls, arbitrary MMIO API or Apps SMMU. */
#include "open_smmu_d0.h"
#include <string.h>
#include <limits.h>
const struct osm_range osm_required_ranges[OSM_MAPS]={
 {0x03da0000,0x40000,0}, /* Dedicated GPU SMMU: this power core reads ID0 only. */
 {0x03d97000,0x1000,1},{0x03d99000,0x1000,1},
 {0x00171000,0x1000,1},{0x00100000,0x1000,0},{0x03d91000,0x1000,0}
};
static const uint64_t clocks[4]={0x03d97000,0x00171010,0x00171018,0x03d9911c};
/* CBCR status bits31:28 are volatile. Every other foreign control bit,
 * including MEMNOC HWCG1 and CLK_DIS22, must retain its immutable value. */
#define CONTROL_MASK 0x0ffffffeu
static int owner(struct osm_lease*s){return s->io.owns(s->io.cookie,s->generation)==0?0:OSM_OWNER;}
static int fail(struct osm_lease*s,int e){s->error=e;s->state=(s->attempted||s->refs||s->owned_mask)?OSM_POISONED:OSM_SAFE_FAILED;return e;}
static int location(struct osm_lease*s,uint64_t pa,unsigned *m,uint32_t *off){
 for(unsigned i=0;i<OSM_MAPS;i++)if(pa>=osm_required_ranges[i].pa&&pa-osm_required_ranges[i].pa<=osm_required_ranges[i].bytes-4){*m=i;*off=(uint32_t)(pa-osm_required_ranges[i].pa);return i<s->mapped?0:OSM_IO;}return OSM_ARGUMENT;
}
static int rd(struct osm_lease*s,uint64_t pa,uint32_t*v){unsigned m;uint32_t off;int e=owner(s);if(e)return e;if((e=location(s,pa,&m,&off)))return e;if(s->io.read32(s->io.cookie,s->maps[m],off,v)||*v==UINT32_MAX)return OSM_IO;return 0;}
static int wr_clock(struct osm_lease*s,unsigned index,uint32_t value){
 unsigned m;uint32_t off;int e;if(index>=4||(e=owner(s)))return OSM_OWNER;
 if((value&CONTROL_MASK)!=(s->before[index]&CONTROL_MASK))return OSM_FOREIGN;
 if((e=location(s,clocks[index],&m,&off))||!osm_required_ranges[m].writable)return OSM_ARGUMENT;
 s->attempted=1;s->writes++; /* Journal BEFORE the call; failure may have written. */
 if(s->io.write32(s->io.cookie,s->maps[m],off,value))return OSM_IO;
 s->io.barrier(s->io.cookie);return 0;
}
/* Physical on-state prerequisite, not an RPMh voltage/power lease. An off or
 * HW-controlled CX fails BEFORE ANY STORE. No cold power-up, rail vote, GDSCR,
 * PLL programming, ROOT/UPDATE, reset or security-register writes exist here. */
static int parents(struct osm_lease*s,unsigned final){
 uint32_t cfgahb,cx,hw,reset,cxreset,cmd,cfg,vote,pll[2][5],external[2],ap[2];int e;
 const uint64_t pp[5]={0x00100000,0x00100004,0x00100010,0x00100014,0x00100018};
 if((e=rd(s,0x00171004,&cfgahb)))return e;if(!(cfgahb&1))return OSM_PARENT;
 if((e=rd(s,0x03d99108,&cx))||(e=rd(s,0x03d9953c,&hw)))return e;
 s->last_cx=cx;s->last_hw=hw;if(!(cx&0x80000000u)||!(hw&0x80000000u)||(cx&7))return OSM_POWER_OFF;
 if((e=rd(s,0x00171000,&reset))||(e=rd(s,0x03d99104,&cxreset)))return e;if((reset|cxreset)&1)return OSM_PARENT;
 for(unsigned k=0;k<2;k++){
  for(unsigned i=0;i<5;i++)if((e=rd(s,pp[i],&pll[k][i])))return e;
  if(s->io.parent_votes(s->io.cookie,&external[k],&ap[k]))return OSM_PARENT;
 }
 for(unsigned i=0;i<5;i++)if(pll[0][i]!=pll[1][i])return OSM_FOREIGN;
 if(external[0]!=external[1]||ap[0]!=ap[1])return OSM_FOREIGN;
 if((pll[0][0]&0x80000004u)!=0x80000004u||!(pll[0][4]&(1u<<25))||!(ap[0]&1)||pll[0][3]>0xffff)return OSM_PARENT;
 uint64_t q=UINT64_C(19200000)*(((uint64_t)(pll[0][2]&0xffff)<<16)+pll[0][3]);
 if(q!=UINT64_C(600000000)*65536u)return OSM_PARENT;
 vote=external[0];if(!(vote&0x8000u))return OSM_PARENT;
 if((e=rd(s,0x03d993ec,&cmd))||(e=rd(s,0x03d993f0,&cfg)))return e;
 s->last_root=cmd;s->last_cfg=cfg;
 /* Existing source HWCTL200MHz configuration; allow gated ROOT_OFF before
  * child votes, require ROOT_OFF0 afterward. Never rewrite a foreign rate. */
 if((cmd&0xf1u)||(cfg&0x0010371fu)!=0x00100505u||(final&&(cmd&0x80000000u)))return OSM_PARENT;
 return 0;
}
/* Exact AHB clk_branch2/HALT_DELAY enable accepts the update_bits request
 * followed by10us, without a BIT0 readback test. Only our captured0->1
 * AHB request gets this narrow policy; all other branches remain strict. */
static int delay_request(struct osm_lease*s,unsigned i){return i==3&&(s->delay_request_mask&8u);}
static int controls(struct osm_lease*s,unsigned i,uint32_t v){
 if((v&CONTROL_MASK)!=(s->before[i]&CONTROL_MASK)){s->reject_reason=1;return 0;}
 if(!delay_request(s,i)&&((v^s->expected[i])&1)){s->reject_reason=2;return 0;}return 1;
}
static void observed(struct osm_lease*s,unsigned i,uint32_t v){s->last_branch[i]=v;if(v&1u)s->bit0_confirmed_mask|=1u<<i;else s->bit0_confirmed_mask&=~(1u<<i);}
static int branch_ready(struct osm_lease*s,unsigned i,uint32_t v){
 if(delay_request(s,i))return 1; /* request+delay accepted; not BIT0 confirmed */
 if(!(v&1))return 0; /* Strict Windows write-confirmation profile, explicit. */
 if(i==1&&(v&2))return 1; /* MEMNOC hardware gating: Linux skips halt poll. */
 return i>=2||!(v&0x80000000u); /* DVM/AHB HALT_DELAY; SMMU voted halt. */
}
int osm_unmap_safe(struct osm_lease*s){
 if(!s||s->refs||s->owned_mask||s->state==OSM_ACTIVE||s->state==OSM_PREPARING||s->state==OSM_RELEASING||s->state==OSM_POISONED)return OSM_UNCERTAIN;
 while(s->mapped){unsigned i=--s->mapped;s->io.unmap(s->io.cookie,s->maps[i],osm_required_ranges[i].bytes);s->maps[i]=0;}return 0;
}
int osm_witness(struct osm_lease*s,uint64_t generation){
 int e;uint32_t v;if(!s||s->state!=OSM_ACTIVE||s->generation!=generation)return OSM_OWNER;
 if((e=parents(s,1)))return fail(s,e);
 for(unsigned i=0;i<4;i++){if((e=rd(s,clocks[i],&v)))return fail(s,e);observed(s,i,v);if(!controls(s,i,v)||!branch_ready(s,i,v))return fail(s,OSM_FOREIGN);}
 return 0;
}
int osm_acquire(struct osm_lease*s,const struct osm_ops*o,uint64_t generation){
 int e;uint32_t a,b;
 if(!s||!o||!generation||!o->owns||!o->grant||!o->map||!o->unmap||!o->read32||!o->write32||!o->barrier||!o->delay_us||!o->drained||!o->parent_votes)return OSM_ARGUMENT;
 if(s->state==OSM_ACTIVE){if(s->generation!=generation)return OSM_OWNER;if(s->refs==UINT_MAX)return OSM_OVERFLOW;if((e=osm_witness(s,generation)))return e;s->refs++;return 0;}
 if(s->state!=OSM_NEW)return OSM_UNCERTAIN;
 memset(s,0,sizeof(*s));s->io=*o;s->generation=generation;s->state=OSM_PREPARING;
 if((e=owner(s)))return fail(s,e);
 for(unsigned i=0;i<OSM_MAPS;i++)if(s->io.grant(s->io.cookie,generation,&osm_required_ranges[i]))return fail(s,OSM_OWNER);
 for(unsigned i=0;i<OSM_MAPS;i++){uintptr_t token=0;int result=s->io.map(s->io.cookie,&osm_required_ranges[i],&token);if(token){s->maps[i]=token;s->mapped++;}if(result&&token){s->error=OSM_IO;s->state=OSM_POISONED;return OSM_IO;}if(result||!token){fail(s,OSM_IO);osm_unmap_safe(s);return OSM_IO;}}
 if((e=parents(s,0))){fail(s,e);osm_unmap_safe(s);return e;}
 /* Double-capture all immutable foreign clock control fields before first write. */
 for(unsigned i=0;i<4;i++){if((e=rd(s,clocks[i],&a))||(e=rd(s,clocks[i],&b)))return fail(s,e);if((a&0x0fffffffu)!=(b&0x0fffffffu))return fail(s,OSM_FOREIGN);s->before[i]=b;s->expected[i]=b;}
 for(unsigned i=0;i<4;i++){
  if((e=parents(s,0))||(e=rd(s,clocks[i],&a)))return fail(s,e);
  if(!controls(s,i,a))return fail(s,OSM_FOREIGN);
  s->expected[i]=a|1u;
  if(!(a&1)){s->owned_mask|=1u<<i;if((e=wr_clock(s,i,a|1u)))return fail(s,e);if(i==3)s->delay_request_mask|=8u;}
  /* Borrowed pre-existing votes are NEVER cleared by this owner. */
  if(i>=2)s->io.delay_us(s->io.cookie,10);
  unsigned n;for(n=0;n<200;n++){
   if((e=rd(s,clocks[i],&b)))return fail(s,e);s->polls++;observed(s,i,b);
   if(!controls(s,i,b))return fail(s,OSM_FOREIGN);
   if(branch_ready(s,i,b))break;
   if(i>=2||(i==1&&(b&2)))break;
   s->io.delay_us(s->io.cookie,1);
  }
  if(n==200||!branch_ready(s,i,b))return fail(s,OSM_TIMEOUT);
 }
 s->state=OSM_ACTIVE;s->refs=1;
 if((e=osm_witness(s,generation)))return e;return 0;
}
int osm_release(struct osm_lease*s,uint64_t generation){
 int e;uint32_t v;if(!s||s->state!=OSM_ACTIVE||s->generation!=generation||!s->refs)return OSM_OWNER;
 if((e=osm_witness(s,generation)))return e;
 if(s->refs>1){s->refs--;return 0;}
 if(s->io.drained(s->io.cookie,generation))return OSM_BUSY;
 if((e=osm_witness(s,generation)))return e;
 /* Same-block completion read + barrier before removing any clock vote. */
 if((e=rd(s,0x03da0020,&s->last_id0)))return fail(s,e);s->io.barrier(s->io.cookie);
 s->state=OSM_RELEASING;
 for(unsigned n=4;n;n--){unsigned i=n-1;
  if(!(s->owned_mask&(1u<<i)))continue;
  if((e=parents(s,0))||(e=rd(s,clocks[i],&v)))return fail(s,e);if(!controls(s,i,v))return fail(s,OSM_FOREIGN);
  /* Linux update_bits disable is a no-op when BIT0 already reads0. */
  if((v&1u)&&(e=wr_clock(s,i,v&~1u)))return fail(s,e);s->expected[i]=v&~1u;
  s->io.delay_us(s->io.cookie,10);
  if((e=rd(s,clocks[i],&v)))return fail(s,e);if(!controls(s,i,v))return fail(s,OSM_FOREIGN);
  observed(s,i,v);if(delay_request(s,i)&&(v&1u)){s->reject_reason=3;return fail(s,OSM_UNCERTAIN);}
  s->owned_mask&=~(1u<<i);s->cleared_mask|=1u<<i;s->delay_request_mask&=~(1u<<i);
 }
 s->refs=0;s->state=OSM_RELEASED;s->error=0;return osm_unmap_safe(s);
}
