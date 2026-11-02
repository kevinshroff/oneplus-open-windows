/* Host-only device model: tests packet/fail-closed behavior, NOT hardware. */
#include "g433_cp.h"
#include "gpu_va_layout.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {uint32_t reg[65536];g433_memory mem[4];g433_cp core;unsigned writes,publishes;uint32_t fail_offset;int missing_bv;int revoke,cancel,fail_write,drop,device_completes,backwards;uint64_t clock,read_delay,issue_delay;} model;
static int lease(void*p){return ((model*)p)->revoke;}
static int rd(void*p,uint32_t off,uint32_t*v){model*m=p;assert(!(off&3)&&off/4<65536);m->clock+=m->read_delay;*v=m->reg[off/4];return 0;}
static int wr(void*p,uint32_t off,uint32_t v){model*m=p;assert(!(off&3)&&off/4<65536);m->writes++;if(m->fail_write||(m->fail_offset&&off==m->fail_offset))return -1;if(off==0x808*4&&v==1){if(((uint64_t)m->reg[0xa98]|((uint64_t)m->reg[0xa99]<<32))!=m->mem[1].iova+8){m->missing_bv=1;return -1;}assert(m->mem[1].cpu[2]==0);}m->reg[off/4]=v;if(off==0x807*4&&v==17)m->clock+=m->issue_delay;if(off==0x807*4&&(v==17||v==26)&&m->device_completes)m->mem[1].cpu[1]=v==17?1:2;return 0;}
static int pub(void*p,const volatile uint32_t*c,size_t n){model*m=p;assert(c&&n);m->publishes++;return 0;}
static int acq(void*p,volatile uint32_t*c,size_t n){(void)p;assert(c&&n);return 0;}
static int barrier(void*p){(void)p;return 0;}
static int now(void*p,uint64_t*v){model*m=p;if(m->backwards){*v=m->clock-1;}else{*v=m->clock;m->clock+=10;}return 0;}
static int waitfn(void*p,uint32_t us){(void)p;assert(us==10);return 0;}
static int cancel(void*p){return ((model*)p)->cancel;}
static int fence(void*p,uint32_t*v){model*m=p;*v=m->drop&&m->reg[0x807]==17?1:0;return 0;}
static g433_cp_ops ops(model*m){return(g433_cp_ops){m,lease,rd,wr,pub,acq,barrier,now,waitfn,cancel,fence};}
static void init(model*m){memset(m,0,sizeof(*m));size_t bytes[]={0x8000,0x1000,0x13000,0x1000};uint64_t va[]=OGO_CP_VA_INITIALIZER;for(int i=0;i<4;i++){m->mem[i]=(g433_memory){calloc(1,bytes[i]),va[i],bytes[i]};assert(m->mem[i].cpu);}m->clock=100;}
static void done(model*m){for(int i=0;i<4;i++)free((void*)m->mem[i].cpu);}
static void packets(model*m){assert(((uint64_t)m->reg[0x800]|((uint64_t)m->reg[0x801]<<32))==m->mem[0].iova);assert(((uint64_t)m->reg[0x804]|((uint64_t)m->reg[0x805]<<32))==m->mem[1].iova);assert(((uint64_t)m->reg[0x830]|((uint64_t)m->reg[0x831]<<32))==m->mem[2].iova);volatile uint32_t*w=m->mem[0].cpu;assert(((uint64_t)m->reg[0xa98]|((uint64_t)m->reg[0xa99]<<32))==m->mem[1].iova+8);assert(m->reg[0x802]==0x20c&&m->reg[0x807]==17&&m->reg[0x808]==1);assert((w[0]&0x7fff)==1&&((w[0]>>16)&0x7f)==0x17&&w[1]==(1u<<27));assert(((w[2]>>16)&0x7f)==0x48&&(w[2]&0x7fff)==7&&w[3]==0x94b&&w[4]==3&&w[5]==0x20000000&&w[6]==2&&w[7]==(uint32_t)m->mem[3].iova&&w[8]==(uint32_t)(m->mem[3].iova>>32)&&w[9]==0x80000000);assert(w[11]==1&&((w[12]>>16)&0x7f)==0x46&&w[13]==0x88000031&&w[14]==(uint32_t)(m->mem[1].iova+4)&&w[15]==(uint32_t)((m->mem[1].iova+4)>>32)&&w[16]==1);assert(m->mem[3].cpu[3]==(54u|(16u<<8)));}
int main(void){model*m=malloc(sizeof(*m));assert(m);g433_cp_ops o;unsigned cases=0;
 init(m);o=ops(m);m->mem[1].bytes=8;assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_ARGUMENT&&m->writes==0);done(m);cases++;
 init(m);o=ops(m);m->mem[1].iova=m->mem[0].iova;assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_ARGUMENT&&m->writes==0);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_PENDING);packets(m);m->mem[1].cpu[2]=1;assert(m->mem[1].cpu[1]==0&&g433_cp_poll(&m->core)==G433_PENDING&&m->core.completed==0);done(m);cases++;
 init(m);o=ops(m);m->device_completes=1;assert(g433_cp_run(&m->core,&o,m->mem,100)==G433_OK&&m->core.completed==1&&m->core.stage==6);packets(m);done(m);cases++;
 init(m);o=ops(m);m->drop=1;assert(g433_cp_run(&m->core,&o,m->mem,100)==G433_IO&&m->core.poisoned&&m->core.may_run&&m->core.completed==0);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_run(&m->core,&o,m->mem,100)==G433_TIMEOUT&&m->core.poisoned&&m->mem[1].cpu[1]==0);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_PENDING);m->mem[1].cpu[1]=2;assert(g433_cp_poll(&m->core)==G433_CORRUPT);done(m);cases++;
 init(m);o=ops(m);m->fail_write=1;assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_IO&&m->core.poisoned&&m->writes==1);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_PENDING);m->revoke=1;assert(g433_cp_poll(&m->core)==G433_LEASE);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_PENDING);m->cancel=1;assert(g433_cp_poll(&m->core)==G433_CANCELLED);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_PENDING);m->clock=1;m->backwards=1;assert(g433_cp_poll(&m->core)==G433_CORRUPT);done(m);cases++;
 init(m);o=ops(m);assert(g433_cp_begin(&m->core,&o,m->mem,100)==G433_PENDING);m->mem[1].cpu[1]=1;m->clock=300;assert(g433_cp_poll(&m->core)==G433_TIMEOUT&&m->core.completed==0);done(m);cases++;
 init(m);o=ops(m);m->device_completes=1;assert(g433_cp_run(&m->core,&o,m->mem,100)==G433_OK);assert(g433_cp_secure_run(&m->core,100)==G433_OK&&m->core.stage==9&&m->core.completed==2&&m->reg[0x807]==26);assert(((m->mem[0].cpu[17]>>16)&0x7f)==0x66&&m->mem[0].cpu[18]==0&&m->mem[0].cpu[20]==2&&m->mem[0].cpu[25]==2);done(m);cases++;
 init(m);o=ops(m);m->device_completes=1;assert(g433_cp_run(&m->core,&o,m->mem,100)==G433_OK);m->device_completes=0;assert(g433_cp_secure_run(&m->core,100)==G433_TIMEOUT&&m->core.completed==1&&m->core.issued==2);done(m);cases++;
 init(m);assert(g433_cp_secure_begin(&m->core,100)==G433_STATE&&m->writes==0);done(m);cases++;
 init(m);o=ops(m);m->read_delay=10000;m->device_completes=1;assert(g433_cp_run(&m->core,&o,m->mem,500000)==G433_OK&&m->core.setup_done_us-m->core.setup_begin_us>500000&&m->core.completed==1);done(m);cases++;
 init(m);o=ops(m);m->read_delay=100000;m->device_completes=1;assert(g433_cp_run(&m->core,&o,m->mem,500000)==G433_TIMEOUT&&m->core.poisoned&&!m->core.may_run&&!m->writes);done(m);cases++;
 init(m);o=ops(m);m->issue_delay=1000000;m->device_completes=1;assert(g433_cp_run(&m->core,&o,m->mem,500000)==G433_OK&&m->core.issue_posted_us>=1000000&&m->core.completed==1);done(m);cases++;
 init(m);o=ops(m);m->issue_delay=6000000;assert(g433_cp_run(&m->core,&o,m->mem,500000)==G433_TIMEOUT&&m->core.poisoned&&m->core.may_run&&m->core.issued==1);done(m);cases++;
 for(unsigned i=0;i<2;i++){init(m);o=ops(m);m->fail_offset=(0xa98+i)*4;assert(g433_cp_run(&m->core,&o,m->mem,100)==G433_IO&&m->core.poisoned&&!m->core.may_run&&m->reg[0x808]==0);done(m);cases++;}
 free(m);printf("{\"host_model_cases\":%u,\"native_evidence\":false,\"result\":\"pass\"}\n",cases);return 0;}
