/* SPDX-License-Identifier: MIT */
#include "gmu_clock.h"
#include <string.h>
#include <limits.h>
static const uint64_t leaf[6]={0x03d9913c,0x03d99144,0x00171154,0x00171010,0x03d9911c,0x03d99148};
#define CMD UINT64_C(0x03d99318)
#define CFG UINT64_C(0x03d9931c)
#define CFG_MASK 0x0010371fu
#define CFG_220 0x00100303u
#define FOREIGN 0x0ffffffeu
static enum gmc_error fail(GMC_LEASE*s,enum gmc_error e){s->error=e;s->state=s->attempted?GMC_POISONED:GMC_REFUSED;return e;}
static int current(GMC_LEASE*s){return s->io.current(s->io.cookie,s->generation)==0;}
static enum gmc_error rd(GMC_LEASE*s,uint64_t a,uint32_t*v){if(!current(s))return GMC_OWNER;s->reads++;s->last_pa_low=(uint32_t)a;if(s->io.read(s->io.cookie,a,v)||*v==UINT32_MAX)return GMC_IO_ERROR;s->last_word=*v;return GMC_OK;}
static enum gmc_error wr(GMC_LEASE*s,uint64_t a,uint32_t before,uint32_t after){
 if(!current(s))return GMC_OWNER;s->attempted=1;s->state=GMC_MUTATING;s->writes++;if(s->io.write(s->io.cookie,a,before,after))return GMC_IO_ERROR;s->io.barrier(s->io.cookie);return GMC_OK;
}
static enum gmc_error pll(GMC_LEASE*s){
 static const uint64_t reg[6]={0x03d91000,0x03d91004,0x03d91010,0x03d91014,0x03d91018,0x03d9101c};
 uint32_t a[6],b[6];enum gmc_error e;for(unsigned k=0;k<6;k++)if((e=rd(s,reg[k],&a[k])))return e;
 for(unsigned k=0;k<6;k++)if((e=rd(s,reg[k],&b[k])))return e;
 for(unsigned k=0;k<6;k++)if(a[k]!=b[k])return GMC_FOREIGN;
 memcpy(s->pll,b,sizeof(b));
 /* Lucid OLE aliases EVO: PLL_MODE LOCK/RESET_N/OUTCTRL, OPMODE RUN,
  * low16 L and alpha. Read-only source440MHz profile has <1kHz quantization.
  * Output controls must actually expose the main output. Never enable or
  * calibrate PLL here: that needs the actual MX/PLL owner/voltage contract. */
 if((b[3]&0xffff0000u)||(b[0]&0x80000005u)!=0x80000005u||b[1]!=1||!(b[4]&1u))return GMC_NEED_PLL_OWNER;
 uint64_t rate=UINT64_C(19200000)*(((uint64_t)(b[2]&0xffff)<<16)+(b[3]&0xffff));
 if(rate<UINT64_C(439999000)*65536||rate>UINT64_C(440001000)*65536)return GMC_NEED_PLL_OWNER;
 return GMC_OK;
}
static enum gmc_error root_current(GMC_LEASE*s,unsigned final){enum gmc_error e;uint32_t c,v;if((e=pll(s))||(e=rd(s,CMD,&c))||(e=rd(s,CFG,&v)))return e;if((c&0x7fffffecu)!=(s->root_cmd_before&0x7fffffecu)||(c&(s->root_dirty_allowed?0xe3u:0xf3u))||(final&&(c&0x80000000u))||v!=s->root_expected)return GMC_FOREIGN;return GMC_OK;}
static enum gmc_error update(GMC_LEASE*s,uint32_t before,uint32_t after){
 enum gmc_error e;uint32_t c,v;if((e=rd(s,CMD,&c)))return e;if(c&0xf3u)return GMC_FOREIGN;
 /* Temporary ROOT_EN safeguards source mux/HID update; it is never retained
  * as a synthetic permanent force. Immutable unrelated CFG bits preserved. */
 if((e=wr(s,CMD,c,c|2u)))return e;c&=0x7fffffffu; /* ROOT_OFF is status, not immutable control. */
 unsigned n;for(n=0;n<200;n++){if((e=rd(s,CMD,&v)))return e;s->polls++;if(!(v&0x80000000u))break;s->io.wait1us(s->io.cookie);}if(n==200)return GMC_TIMEOUT;
 if((e=rd(s,CFG,&v)))return e;if(v!=before)return GMC_FOREIGN;
 if((e=wr(s,CFG,before,after))||(e=rd(s,CFG,&v)))return e;if(v!=after)return GMC_FOREIGN;
 /* The exact owned CFG write may set DIRTY_CFG4. Source update_config
  * waits only UPDATE0 clear; it neither clears nor requires DIRTY4 clear. */
 s->root_dirty_allowed=1;
 if((e=rd(s,CMD,&v)))return e;if((v&0x7fffffefu)!=(c|2u))return GMC_FOREIGN;
 if((e=wr(s,CMD,v,v|1u)))return e;
 for(n=0;n<500;n++){if((e=rd(s,CMD,&v)))return e;s->polls++;if(!(v&1u))break;s->io.wait1us(s->io.cookie);}if(n==500)return GMC_TIMEOUT;
 if((v&0x7fffffefu)!=(c|2u))return GMC_FOREIGN;if((e=wr(s,CMD,v,v&~2u)))return e;
 if((e=rd(s,CFG,&v)))return e;return v==after?GMC_OK:GMC_FOREIGN;
}
static enum gmc_error leaves(GMC_LEASE*s){enum gmc_error e;for(unsigned i=0;i<6;i++){uint32_t v;if((e=rd(s,leaf[i],&v)))return e;s->raw[i]=v;if((v&FOREIGN)!=(s->before[i]&FOREIGN))return GMC_FOREIGN;if(v&1)s->bit0_confirmed_mask|=1u<<i;else s->bit0_confirmed_mask&=~(1u<<i);
 if(i==4&&(s->delay_request_mask&(1u<<i)))continue;
 if(!(v&1))return GMC_FOREIGN;
 /* DDRSS HALT_SKIP; MEMNOC HWCG skips halt; other selected leaves use
  * source voted or ordinary halt. NOC FSM ON is accepted per branch2. */
 if(i==2||(i==3&&(v&2)))continue;
 if(v&0x80000000u)return GMC_PARENT;
 }return GMC_OK;}
enum gmc_error GmcWitness(GMC_LEASE*s){enum gmc_error e;if(!s||s->state!=GMC_HELD||!s->refs)return GMC_OWNER;if((e=root_current(s,1))||(e=leaves(s)))return fail(s,e);return GMC_OK;}
enum gmc_error GmcAcquire(GMC_LEASE*s,const GMC_IO*io){
 enum gmc_error e;uint32_t c,v;if(!s||!io||!io->generation||!io->current||!io->read||!io->write||!io->barrier||!io->wait1us)return GMC_ARGUMENT;
 if(s->state==GMC_HELD){if(s->generation!=io->generation||s->io.cookie!=io->cookie||s->refs==UINT_MAX)return GMC_OWNER;if((e=GmcWitness(s)))return e;s->refs++;return GMC_OK;}
 if(s->state!=GMC_NEW)return GMC_OWNER;memset(s,0,sizeof(*s));s->io=*io;s->generation=io->generation;
 if((e=pll(s))||(e=rd(s,CMD,&c))||(e=rd(s,CFG,&s->root_before)))return fail(s,e);if(c&0xf3u)return fail(s,GMC_FOREIGN);
 s->root_cmd_before=c;s->root_expected=(s->root_before&~CFG_MASK)|CFG_220;
 /* Refuse rerating a live GMU branch; no HFI/DCVS or PLL reprogramming. */
 for(unsigned i=0;i<6;i++){uint32_t a;if((e=rd(s,leaf[i],&a))||(e=rd(s,leaf[i],&v)))return fail(s,e);if((a&0x0fffffffu)!=(v&0x0fffffffu))return fail(s,GMC_FOREIGN);s->before[i]=v;}
 if(s->root_expected!=s->root_before){uint32_t gxleaf;if((e=rd(s,UINT64_C(0x03d990bc),&gxleaf)))return fail(s,e);if((s->before[0]|gxleaf)&1)return fail(s,GMC_FOREIGN);s->root_owned=1;if((e=update(s,s->root_before,s->root_expected)))return fail(s,e);}
 for(unsigned i=0;i<6;i++){
  if((e=root_current(s,0))||(e=rd(s,leaf[i],&v)))return fail(s,e);if((v&0x0fffffffu)!=(s->before[i]&0x0fffffffu))return fail(s,GMC_FOREIGN);
  /* The existing four-clock broker owns aggregate AHB request semantics.
   * io.current proves that actual lease/ref ledger each time. Borrow it;
   * do not issue a second write or independently disable its shared bit. */
  if(i==4)s->delay_request_mask|=1u<<i;
  if(i!=4&&!(v&1)){s->owned_mask|=1u<<i;if((e=wr(s,leaf[i],v,v|1)))return fail(s,e);if(i==4)s->delay_request_mask|=1u<<i;}
  if(i==4)for(unsigned d=0;d<10;d++)s->io.wait1us(s->io.cookie);
  unsigned n;for(n=0;n<200;n++){if((e=rd(s,leaf[i],&v)))return fail(s,e);s->raw[i]=v;s->polls++;
   if((v&FOREIGN)!=(s->before[i]&FOREIGN))return fail(s,GMC_FOREIGN);
   if(i==4&&(s->delay_request_mask&(1u<<i)))break;
   if((v&1)&&(i==2||(i==3&&(v&2))||!(v&0x80000000u)))break;s->io.wait1us(s->io.cookie);
  }if(n==200)return fail(s,GMC_TIMEOUT);
 }
 s->state=GMC_HELD;s->refs=1;return GmcWitness(s);
}
enum gmc_error GmcReleaseCold(GMC_LEASE*s){
 enum gmc_error e;uint32_t v;if((e=GmcWitness(s)))return e;if(s->refs>1){s->refs--;return GMC_OK;}
 for(unsigned n=6;n;n--){unsigned i=n-1;if(!(s->owned_mask&(1u<<i)))continue;
  if((e=root_current(s,0))||(e=rd(s,leaf[i],&v)))return fail(s,e);if((v&FOREIGN)!=(s->before[i]&FOREIGN))return fail(s,GMC_FOREIGN);
  /* clk_branch2_aon_ops has NO disable for CX_GMU and DDRSS. Drop
   * the logical reference only; never claim their enables were restored. */
  if(i==0||i==2){s->no_disable_left_mask|=1u<<i;s->request_dropped_mask|=1u<<i;s->owned_mask&=~(1u<<i);continue;}
  unsigned wrote=v&1u;if(wrote&&(e=wr(s,leaf[i],v,v&~1u)))return fail(s,e);
  for(unsigned j=0;j<10;j++)s->io.wait1us(s->io.cookie);
  if(i==1){unsigned n;for(n=0;n<200;n++){if((e=rd(s,leaf[i],&v)))return fail(s,e);s->polls++;if(v&0x80000000u)break;s->io.wait1us(s->io.cookie);}if(n==200)return fail(s,GMC_TIMEOUT);}else if((e=rd(s,leaf[i],&v)))return fail(s,e);
  s->raw[i]=v;if((v&FOREIGN)!=(s->before[i]&FOREIGN)||(v&1))return fail(s,GMC_FOREIGN);
  s->owned_mask&=~(1u<<i);s->request_dropped_mask|=1u<<i;if(wrote)s->write_cleared_mask|=1u<<i;s->delay_request_mask&=~(1u<<i);
 }
 if(s->root_owned){
  /* CX_GMU is AON: clk_disable has no hardware disable. CCF retains the
   * configured rate too. Never rerate that enabled consumer during abort.
   * Drop only this logical rate request; record the configured rate left. */
  if((e=root_current(s,0)))return fail(s,e);
  s->root_left_configured=1;s->root_owned=0;
 }
 s->refs=0;s->state=GMC_RELEASED;s->error=GMC_OK;return GMC_OK;
}
