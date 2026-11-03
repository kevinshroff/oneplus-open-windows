#include "qtb_once.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct model {uint64_t regs[16],time;uint32_t ctl,fsr;unsigned calls,failat,finish,uncertain,writes,starts;int poison,expire,foreign,noack,nodone,injectfault,expire_on_start;};
static int edge(struct model*m){return ++m->calls==m->failat;}
static int acquire(void*x,uint64_t*i,uint64_t*p){struct model*m=x;if(edge(m))return -1;*i=0x100000;*p=0x240000;return 0;}
static int current(void*x){return ((struct model*)x)->poison;}
static int cleanup(void*x){return ((struct model*)x)->expire;}
static unsigned idx(unsigned r){assert(r>=Q_REQ&&r<=Q_OUT&&!(r&7));return (r-Q_REQ)/8;}
static int rd(void*x,unsigned r,uint64_t*v){struct model*m=x;if(edge(m))return -1;if(r==Q_ACK)*v=m->noack?0:m->regs[0]&1;else if(r==Q_STATUS)*v=m->starts&&!m->nodone?1:0;else if(r==Q_OUT)*v=(UINT64_C(0x240000)<<12)|(m->starts&&m->injectfault?1:0);else *v=m->regs[idx(r)];return 0;}
static int wr(void*x,unsigned r,uint64_t v){struct model*m=x;m->writes++;assert(r==Q_REQ||r==Q_IN0||r==Q_IN1||r==Q_IN2||r==Q_TRIGGER);if(r==Q_IN0)assert(v==0);if(r==Q_IN1)assert(v==0x3408);if(r==Q_IN2)assert(v==0x100000);if(r==Q_TRIGGER&&v){assert(!m->starts++);assert((m->regs[0]&1)&&!(m->ctl&0xc0));}m->regs[idx(r)]=v;if(r==Q_TRIGGER&&v&&m->expire_on_start)m->expire=1;if(r==Q_TRIGGER&&v&&m->foreign)m->regs[0]|=2;return edge(m)?-1:0;}
static int rc(void*x,uint32_t*v){struct model*m=x;if(edge(m))return -1;*v=m->ctl;return 0;}
static int wc(void*x,uint32_t v){struct model*m=x;assert(v==0xc00127||v==(0xc00127&~0xc0u));m->ctl=v;return edge(m)?-1:0;}
static int faults(void*x,uint32_t*f,uint64_t*a,uint32_t*s,uint32_t*o){struct model*m=x;if(edge(m))return -1;*f=m->fsr|(m->starts&&m->injectfault?1:0);*a=0x111;*s=0x222;*o=0;if(m->starts&&m->injectfault)m->poison=1;return 0;}
static int sync32(void*x){return edge(x)?-1:0;}
static uint64_t now(void*x){return ((struct model*)x)->time++;}
static void finish(void*x,int u){struct model*m=x;m->finish++;m->uncertain=u;}
static struct qtb_io ops(struct model*m){struct qtb_io o={m,acquire,current,cleanup,rd,wr,rc,wc,faults,sync32,now,finish};return o;}
static void init(struct model*m){memset(m,0,sizeof(*m));m->ctl=0xc00127;}
int main(void){struct model m;struct qtb_report r;struct qtb_io o;
 init(&m);o=ops(&m);
#if !OPEN_QTB_WITNESS
 assert(qtb_once(&o,&r)==QTB_DISABLED&&m.calls==0&&m.writes==0);puts("default-off zero callbacks");return 0;
#else
 assert(qtb_once(&o,&r)==QTB_MATCH&&r.cleanup_restored&&r.out==(UINT64_C(0x240000)<<12)&&r.extracted==0x240000&&r.expected_pfn==0x240&&m.finish==1&&!m.uncertain&&m.starts==1&&m.ctl==0xc00127&&m.regs[0]==0&&m.regs[idx(Q_TRIGGER)]==0);
 unsigned total=m.calls;
 /* Every returned read/write failure, including writes that reached hardware,
  * must terminate, never replay injection and preserve leases via finish. */
 for(unsigned n=1;n<=total;n++){init(&m);m.failat=n;o=ops(&m);qtb_once(&o,&r);assert(m.starts<=1&&m.finish==(n==1?0u:1u));if(n>1)assert(m.uncertain||r.result==QTB_MATCH);if(r.cleanup_restored)assert(m.ctl==0xc00127&&m.regs[0]==0&&m.regs[idx(Q_TRIGGER)]==0);}
 init(&m);m.regs[0]=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_REFUSED&&m.writes==0);
 init(&m);m.regs[idx(Q_TRIGGER)]=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_REFUSED&&m.writes==0);
 init(&m);m.fsr=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_REFUSED&&m.writes==0);
 init(&m);m.injectfault=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_FAULT&&m.poison&&r.cleanup_restored&&r.fsr==1&&r.far==0x111&&m.ctl==0xc00127&&m.regs[0]==0&&m.uncertain);
 init(&m);m.noack=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_HALT_TIMEOUT&&r.cleanup_restored&&m.starts==0&&r.halt_us>=100);
 init(&m);m.nodone=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_TIMEOUT&&r.cleanup_restored&&m.starts==1&&r.ecats_us>=100);
 init(&m);m.expire_on_start=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_IO&&r.uncertain&&!r.cleanup_restored&&m.uncertain&&m.regs[idx(Q_TRIGGER)]==1);
 init(&m);m.foreign=1;o=ops(&m);assert(qtb_once(&o,&r)==QTB_IO&&r.uncertain&&m.regs[0]==3); /* never overwrite foreign bits */
 printf("poison cleanup + timeouts + lost capability + foreign bits + success/rawunits + %u returned-failure boundaries + foreign/pre-fault refusal PASS\n",total);
 return 0;
#endif
}
