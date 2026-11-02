#include "cold_hold.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {unsigned fail_halt,gx,halt,writes,tcs_reads;} SIM;
static int current(void*x,uint64_t g){(void)x;return g==1?0:-1;}
static int readreg(void*x,unsigned b,uint32_t o,uint32_t*v){SIM*s=x;
 if(b==CGH_CORE){*v=o==0x14000?1:o==0x14340?s->gx:0;return 0;}
 if(b==CGH_RSC){s->tcs_reads++;*v=0;return 0;}
 if(o==0xf114&&s->fail_halt)return -1;
 *v=s->halt;return 0;}
static int writehalt(void*x,uint32_t old,uint32_t next){SIM*s=x;assert(old==s->halt);s->halt=next;s->writes++;return 0;}
static void noop(void*x){(void)x;}
int main(void){SIM sim={.fail_halt=1,.gx=1};CGH_HOLD h={0};
 CGH_IO io={&sim,1,current,readreg,writehalt,noop,noop};
 assert(CghAcquire(&h,&io,1,2)==CGH_IO_ERROR);
 assert(h.state==CGH_REFUSED&&!h.owned&&!h.deferred&&!sim.writes);assert(h.sampled_mask==0xff&&h.cold_fail_mask==0);
 memset(&h,0,sizeof h);sim.fail_halt=0;sim.gx=2;sim.tcs_reads=0;
 assert(CghAcquire(&h,&io,1,2)==CGH_NOT_COLD);assert(!sim.tcs_reads&&!sim.writes);assert(h.sampled_mask==0xf&&h.cold_fail_mask==4);
 memset(&h,0,sizeof h);sim.gx=1;
 assert(CghAcquire(&h,&io,1,2)==CGH_OK);assert(h.state==CGH_HELD&&h.owned&&sim.writes==1);
 assert(h.sampled_mask==0x3ff);assert(CghCheck(&h)==CGH_OK);assert(CghReleaseToReset(&h,2)==CGH_OK);
 assert(h.state==CGH_RELEASED&&!h.owned&&sim.writes==2);assert(CghCheckReleased(&h)==CGH_OK);
 h.deferred=1;assert(CghCheckReleased(&h)==CGH_OWNER);
 puts("PASS: IO failure refuses without ownership; gx=2 rejects before TCS; real halt/ACK acquire/release; deferred rejects");
}
