#include "cold_hold.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {uint32_t halt,ack,reset,hfi,gx,fence;unsigned writes,reads,failwrite,drop,revoked;} MODEL;
static int current(void*p,uint64_t g){return ((MODEL*)p)->revoked||g!=1?-1:0;}
static int readreg(void*p,unsigned b,uint32_t o,uint32_t*v){MODEL*m=p;m->reads++;
 if(b==CGH_GPU){*v=o==0xf114?m->halt:m->ack;return 0;}
 if(b==CGH_RSC){*v=1;return 0;}
 switch(o){case 0x14000:*v=m->reset;break;case 0x14600:*v=m->hfi;break;case 0x14340:*v=m->gx;break;case 0x24c40:*v=m->fence;break;default:return -1;}return 0;}
static int writehalt(void*p,uint32_t before,uint32_t next){MODEL*m=p;assert(before==8&&next==0&&m->halt==8);m->writes++;if(m->failwrite)return -1;if(!m->drop)m->halt=0;return 0;}
static void nop(void*p){(void)p;}
static CGH_IO ops(MODEL*m){return(CGH_IO){m,1,current,readreg,writehalt,nop,nop};}
static MODEL fresh(void){return(MODEL){.halt=8,.ack=3,.reset=1,.gx=3};}
int main(void){MODEL m=fresh();CGH_IO io=ops(&m);CGH_HOLD h={0};unsigned cases=0;
 assert(CghResetAcquire(&h,&io,1)==CGH_OK&&h.state==CGH_RESET_QUIESCENT&&h.reset_mode&&!h.owned&&!h.attempted&&!m.writes);cases++;
 assert(CghCheck(&h)==CGH_OWNER);assert(CghResetCheck(&h)==CGH_OK);
 assert(CghResetUnhaltForBoot(&h)==CGH_OK&&h.state==CGH_BOOT_RELEASED&&!h.owned&&m.writes==1&&m.halt==0&&m.ack==3);
 assert(CghResetCheckBootReleased(&h)==CGH_OK);assert(CghResetUnhaltForBoot(&h)==CGH_OWNER&&m.writes==1);cases++;
 m=fresh();io=ops(&m);memset(&h,0,sizeof(h));assert(CghResetAcquire(&h,&io,2)==0);assert(CghResetReleaseUnpublished(&h)==0&&h.state==CGH_RESET_RELEASED&&m.halt==8&&!m.writes);assert(CghResetCheckReleased(&h)==0);assert(CghResetUnhaltForBoot(&h)==CGH_OWNER);cases++;
 for(unsigned i=0;i<7;i++){m=fresh();switch(i){case 0:m.reset=0;break;case 1:m.hfi=1;break;case 2:m.gx=2;break;case 3:m.gx=1;break;case 4:m.fence=1;break;case 5:m.halt=10;break;case 6:m.ack=2;break;}
 io=ops(&m);memset(&h,0,sizeof(h));assert(CghResetAcquire(&h,&io,3)!=0&&!m.writes&&!h.owned&&h.state==CGH_REFUSED);cases++;}
 for(unsigned i=0;i<4;i++){m=fresh();io=ops(&m);memset(&h,0,sizeof(h));assert(CghResetAcquire(&h,&io,4)==0);
 if(i==0)m.revoked=1;if(i==1)m.reset=0;if(i==2)m.failwrite=1;if(i==3)m.drop=1;
 assert(CghResetUnhaltForBoot(&h)!=0&&!h.owned);assert(m.writes==(i>=2?1u:0u));assert(h.state==(i>=2?CGH_POISONED:CGH_REFUSED));assert(CghResetUnhaltForBoot(&h)!=0);cases++;}
 printf("PASS: %u actual cold-reset core cases; HALT8 preserved until single boot-unhalt, ACK3 never ownership; no native hardware evidence\n",cases);
}
