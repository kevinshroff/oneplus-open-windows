/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Register/packet/list contracts from pinned NativeAdreno A740 and PM4.
 * No physical addresses, private SMMU writes, synthetic firmware or fences.
 */
#include "g433_cp.h"
#include "vendor/AdrenoPM4.h"
#include "g456_tables.h"
#define REG(x) ((uint32_t)(x)*4u)
static g433_status fail(g433_cp*c,g433_status s){c->status=s;c->poisoned=1;return s;}
static int lease(g433_cp*c){return c->ops.cancelled(c->ops.cookie)||c->ops.lease(c->ops.cookie);}
static int readreg(g433_cp*c,uint32_t r,uint32_t*v){return lease(c)||c->ops.read(c->ops.cookie,REG(r),v);}
static int writereg(g433_cp*c,uint32_t r,uint32_t v){if(lease(c))return -1;c->writes++;return c->ops.write(c->ops.cookie,REG(r),v);}
static int span(const g433_memory*m){return m->cpu&&!((uintptr_t)m->cpu&3)&&m->bytes&&!(m->bytes&4095)&&m->iova&&!(m->iova&4095)&&m->iova<(UINT64_C(1)<<48)&&m->bytes<=(UINT64_C(1)<<48)-m->iova&&(uintptr_t)m->cpu<=UINTPTR_MAX-m->bytes;}
static int overlap(uint64_t a,size_t n,uint64_t b,size_t m){return a<b+m&&b<a+n;}
static int publish(g433_cp*c,const g433_memory*m){return lease(c)||c->ops.publish(c->ops.cookie,m->cpu,m->bytes);}
static g433_status tick(g433_cp*c,uint64_t*out){
 if(c->ops.now(c->ops.cookie,out))return fail(c,G433_IO);
 if(c->time_seen&&*out<c->last)return fail(c,G433_CORRUPT);
 c->last=*out;c->time_seen=1;return G433_OK;
}
g433_status g433_cp_begin(g433_cp*c,const g433_cp_ops*o,const g433_memory m[4],uint64_t timeout){
 uint32_t value=0,status=0,words[17]={0};uint64_t now;
 if(!c||!o||!m||c->attempted||!timeout||timeout>5000000||!o->lease||!o->read||!o->write||!o->publish||!o->acquire||!o->barrier||!o->now||!o->wait||!o->cancelled||!o->fence_status)return G433_ARGUMENT;
 for(unsigned i=0;i<4;i++){if(!span(&m[i]))return G433_ARGUMENT;for(unsigned j=0;j<i;j++)if(overlap(m[i].iova,m[i].bytes,m[j].iova,m[j].bytes)||overlap((uintptr_t)m[i].cpu,m[i].bytes,(uintptr_t)m[j].cpu,m[j].bytes))return G433_ARGUMENT;}
 if(m[0].bytes!=0x8000||(m[0].iova&0x7fff)||m[1].bytes!=4096||m[2].bytes<76720||m[3].bytes<16+(G456IfpcRegs_COUNT+G456PreemptRegs_COUNT)*8||(G456IfpcRegs_COUNT+G456PreemptRegs_COUNT)>255)return G433_ARGUMENT;
 c->ops=*o;c->ring=m[0];c->fence=m[1];c->sqe=m[2];c->pwrup=m[3];c->timeout=timeout;c->attempted=1;c->stage=1;
 if(lease(c))return fail(c,G433_LEASE);
 if(tick(c,&now)!=G433_OK)return c->status;c->begin=now;
 if(o->fence_status(o->cookie,&status)||status)return fail(c,G433_IO);
 /* Actual register values feed the power-up reglist; source cpu_gpu_lock header packs
  * the exact Open IFPC/preemption pair counts and zero dynamic triplets. */
 for(size_t i=0;i<m[3].bytes/4;i++)m[3].cpu[i]=0;
 m[3].cpu[3]=G456IfpcRegs_COUNT|(G456PreemptRegs_COUNT<<8);
 for(size_t i=0;i<(G456IfpcRegs_COUNT+G456PreemptRegs_COUNT);i++){
  uint32_t reg=i<G456IfpcRegs_COUNT?G456IfpcRegs[i]:G456PreemptRegs[i-G456IfpcRegs_COUNT];
  if(readreg(c,reg,&value))return fail(c,G433_IO);
  m[3].cpu[4+2*i]=reg;m[3].cpu[5+2*i]=value;
 }
 for(size_t i=0;i<m[0].bytes/4;i++)m[0].cpu[i]=0;
 for(size_t i=0;i<m[1].bytes/4;i++)m[1].cpu[i]=0; /* never fabricate nonzero completion */
 if(publish(c,&m[2])||publish(c,&m[3])||publish(c,&m[1]))return fail(c,G433_IO);
 c->stage=2;
 const uint32_t regs[]={0x800,(uint32_t)m[0].iova,0x801,(uint32_t)(m[0].iova>>32),0x802,0x20c,
  0x804,(uint32_t)m[1].iova,0x805,(uint32_t)(m[1].iova>>32),0x807,0,0x885,0,
  0x830,(uint32_t)m[2].iova,0x831,(uint32_t)(m[2].iova>>32)};
 for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i+=2)if(writereg(c,regs[i],regs[i+1]))return fail(c,G433_IO);
 if(readreg(c,0x806,&value)||value)return fail(c,G433_STATE);
 if(readreg(c,0x830,&value)||value!=(uint32_t)m[2].iova)return fail(c,G433_IO);
 if(readreg(c,0x831,&value)||value!=(uint32_t)(m[2].iova>>32))return fail(c,G433_IO);
 c->stage=3;
 /* Open gen7_rb_start programs SQE base then CP_SQE_CNTL=1. The actual
  * stopped owner must establish reset/protection before this release. */
 c->may_run=1;
 if(writereg(c,0x808,1))return fail(c,G433_IO);
 if(AdrenoPM4Type7(0x17,1,&words[0])||AdrenoPM4Type7(0x48,7,&words[2])||AdrenoPM4Type4(0x885,1,&words[10])||AdrenoPM4Type7(0x46,4,&words[12]))return fail(c,G433_CORRUPT);
 words[1]=1u<<27;words[3]=0x94b;words[4]=3;words[5]=0x20000000;words[6]=2;
 words[7]=(uint32_t)m[3].iova;words[8]=(uint32_t)(m[3].iova>>32);words[9]=1u<<31;
 words[11]=1;words[13]=0x88000031;words[14]=(uint32_t)(m[1].iova+4);words[15]=(uint32_t)((m[1].iova+4)>>32);words[16]=1;
 for(unsigned i=0;i<17;i++)m[0].cpu[i]=words[i];
 if(publish(c,&m[0])||o->barrier(o->cookie))return fail(c,G433_IO);
 c->stage=4;
 if(o->fence_status(o->cookie,&status)||status)return fail(c,G433_IO);
 /* A failed/dropped WPTR is uncertain. No unconditional success afterretry. */
 if(writereg(c,0x807,17)||o->barrier(o->cookie)||o->fence_status(o->cookie,&status)||status)return fail(c,G433_IO);
 c->issued=1;c->stage=5;c->status=G433_PENDING;return G433_PENDING;
}
g433_status g433_cp_poll(g433_cp*c){
 uint64_t now;uint32_t value;
 if(!c||!c->attempted||c->poisoned||(c->stage!=5&&c->stage!=8&&c->stage!=10))return G433_STATE;
 if(c->ops.cancelled(c->ops.cookie))return fail(c,G433_CANCELLED);
 if(lease(c))return fail(c,G433_LEASE);
 if(c->ops.acquire(c->ops.cookie,c->fence.cpu,c->fence.bytes))return fail(c,G433_IO);
 value=c->fence.cpu[1];c->last_observed=value;c->polls++;
 if(value>c->issued||value<c->completed)return fail(c,G433_CORRUPT);
 if(tick(c,&now)!=G433_OK)return c->status;
 if(now-c->begin>=c->timeout||c->polls>=65536)return fail(c,G433_TIMEOUT);
 if(value==c->issued){
  if(c->stage==10){uint32_t rptr,bv=c->fence.cpu[2];
   if(bv>c->issued)return fail(c,G433_CORRUPT);
   if(readreg(c,0x806,&rptr)||rptr>=c->ring.bytes/4)return fail(c,G433_IO);
   if(bv!=c->issued||rptr!=c->submit_wptr){c->status=G433_PENDING;return G433_PENDING;}
   c->completed=value;c->stage=9;
  }else{c->completed=value;c->stage=c->secure_transition?9:6;if(c->stage==9)c->submit_wptr=26;}
  c->status=G433_OK;return G433_OK;
 }
 c->status=G433_PENDING;return G433_PENDING;
}
g433_status g433_cp_run(g433_cp*c,const g433_cp_ops*o,const g433_memory m[4],uint64_t timeout){
 g433_status s=g433_cp_begin(c,o,m,timeout);
 while(s==G433_PENDING){s=g433_cp_poll(c);if(s==G433_PENDING&&o->wait(o->cookie,10))return fail(c,G433_IO);}
 return s;
}

g433_status g433_cp_secure_begin(g433_cp*c,uint64_t timeout){
 uint32_t w[9]={0},status=0;uint64_t now;
 if(!c||c->poisoned||c->stage!=6||c->completed!=1||c->issued!=1||c->secure_transition||!timeout||timeout>5000000)return G433_STATE;
 if(lease(c))return fail(c,G433_LEASE);
 if(tick(c,&now)!=G433_OK)return c->status;
 c->begin=now;c->timeout=timeout;c->polls=0;c->secure_transition=1;c->stage=7;
 /* Exactly the pinned post-ZAP CP_SET_SECURE_MODE(0); fresh fence2 cannot be
  * satisfied by the already observed init fence1. */
 if(AdrenoPM4Type7(0x66,1,&w[0])||AdrenoPM4Type4(0x885,1,&w[2])||AdrenoPM4Type7(0x46,4,&w[4]))return fail(c,G433_CORRUPT);
 w[1]=0;w[3]=2;w[5]=0x88000031;w[6]=(uint32_t)(c->fence.iova+4);w[7]=(uint32_t)((c->fence.iova+4)>>32);w[8]=2;
 for(unsigned i=0;i<9;i++)c->ring.cpu[17+i]=w[i];
 if(publish(c,&c->ring)||c->ops.barrier(c->ops.cookie)||c->ops.fence_status(c->ops.cookie,&status)||status)return fail(c,G433_IO);
 if(writereg(c,0x807,26)||c->ops.barrier(c->ops.cookie)||c->ops.fence_status(c->ops.cookie,&status)||status)return fail(c,G433_IO);
 c->issued=2;c->stage=8;c->status=G433_PENDING;return G433_PENDING;
}
g433_status g433_cp_secure_run(g433_cp*c,uint64_t timeout){
 g433_status s=g433_cp_secure_begin(c,timeout);
 while(s==G433_PENDING){s=g433_cp_poll(c);if(s==G433_PENDING&&c->ops.wait(c->ops.cookie,10))return fail(c,G433_IO);}
 return s;
}

/* A7xx basic single-context ring submission. Numeric facts and BR/BV order:
 * pinned Linux a6xx_gpu.c:a7xx_submit + Mesa adreno_pm4.xml/A6xx CP_SCRATCH.
 * Deliberately no pagetable switch, statistics or preemption pseudo registers.
 * Full validation and idle proof precede ring writes. */
g433_status g433_cp_submit_begin(g433_cp*c,const g433_ib*ib,size_t count,uint64_t timeout){
 uint32_t n=0,header=0,status=0,rptr,wptr,seq;uint64_t now;
 if(!c||!ib||!count||count>512||!timeout||timeout>5000000)return G433_ARGUMENT;
 if(c->poisoned||c->stage!=9||!c->secure_transition||c->completed!=c->issued||c->issued<2||c->issued>=INT32_MAX)return G433_STATE;
 for(size_t i=0;i<count;i++)if(!ib[i].iova||(ib[i].iova&3)||ib[i].iova>=(UINT64_C(1)<<48)||!ib[i].words||ib[i].words>0xfffff||
   (uint64_t)ib[i].words*4>(UINT64_C(1)<<48)-ib[i].iova)return G433_ARGUMENT;
 if(c->ring.bytes!=0x8000||c->submit_wptr>=8192||c->fence.bytes<12)return G433_STATE;
 if(lease(c))return fail(c,G433_LEASE);
 if(readreg(c,0x806,&rptr)||readreg(c,0x807,&wptr))return fail(c,G433_IO);
 if(rptr>=8192||wptr!=c->submit_wptr)return fail(c,G433_CORRUPT);
 if(rptr!=wptr)return G433_BUSY;
 if(tick(c,&now)!=G433_OK)return c->status;
 seq=c->issued+1;
#define W(v) do{c->ring.cpu[(wptr+n++)&8191]=(uint32_t)(v);}while(0)
#define P7(op,len) do{if(AdrenoPM4Type7((op),(len),&header))return fail(c,G433_CORRUPT);W(header);}while(0)
 P7(0x17,1);W(0x80000001); /* synchronize BR/BV, select render */
 P7(0x17,1);W(3);P7(0x65,1);W(0x101); /* BOTH, IFPC disable */
 for(size_t i=0;i<count;i++){P7(0x3f,3);W(ib[i].iova);W(ib[i].iova>>32);W(ib[i].words);}
 if(AdrenoPM4Type4(0x885,1,&header))return fail(c,G433_CORRUPT);W(header);W(seq);
 P7(0x17,1);W(1);P7(0x46,1);W(24);P7(0x46,1);W(25); /* BR CCU invalidates */
 P7(0x17,1);W(2);P7(0x46,4);W(0x08000031);W(c->fence.iova+8);W((c->fence.iova+8)>>32);W(seq);
 P7(0x17,1);W(1);P7(0x14,4);W(0);W(c->fence.iova+8);W((c->fence.iova+8)>>32);W(seq);
 P7(0x46,4);W(0x88000031);W(c->fence.iova+4);W((c->fence.iova+4)>>32);W(seq);
 P7(0x17,1);W(3);P7(0x65,1);W(0x100); /* BOTH, IFPC enable */
#undef P7
#undef W
 if(n!=37+4*count)return fail(c,G433_CORRUPT);
 c->issued=seq;c->begin=now;c->timeout=timeout;c->polls=0;c->stage=10;
 c->submit_wptr=(wptr+n)&8191;
 /* Ring data must be visible before exposing the new producer index. A failed
  * publish/barrier/WPTR is uncertain and poisons instead of returning success. */
 if(publish(c,&c->ring)||c->ops.barrier(c->ops.cookie)||c->ops.fence_status(c->ops.cookie,&status)||status)return fail(c,G433_IO);
 if(writereg(c,0x807,c->submit_wptr)||c->ops.barrier(c->ops.cookie)||c->ops.fence_status(c->ops.cookie,&status)||status)return fail(c,G433_IO);
 c->status=G433_PENDING;return G433_PENDING;
}
g433_status g433_cp_submit_run(g433_cp*c,const g433_ib*ib,size_t count,uint64_t timeout){
 g433_status s=g433_cp_submit_begin(c,ib,count,timeout);
 while(s==G433_PENDING){s=g433_cp_poll(c);if(s==G433_PENDING&&c->ops.wait(c->ops.cookie,10))return fail(c,G433_IO);}
 return s;
}
