#include "open_smmu_activate.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint64_t regs[0x40000/8];static unsigned cbreads,writes,reads,syncs,waits,deny,stuck,dropTcr,foreign,dropNs,forcedTcr2,forcedSctlr;
static uint32_t*reg32(size_t o){assert(!(o&3)&&o<0x40000);return(uint32_t*)((unsigned char*)regs+o);}
static size_t cb(void){return 0x25000;}
static int proof(void*c,const OSMA_PROOFS*p,unsigned needs,unsigned sid,unsigned bank,unsigned asid,unsigned slot){(void)c;assert(sid==5&&bank==5&&asid==5&&slot==3&&p->Generation==19&&p->StopSerial>=3);if((needs&OSMA_NS_BLOCK)&&!p->NsBlock)return -2;return deny?-91:0;}
static int read32(void*c,size_t at,uint32_t*out){(void)c;reads++;if(at>=0x20000)cbreads++;assert(at<0x29000||at>=0x2a000); /* Never protected CB9. */
 if(at==cb()&&(*reg32(at)&1)&&forcedSctlr){*out=forcedSctlr;return 0;}
 if(at==cb()+0x10&&forcedTcr2){*out=forcedTcr2;return 0;}
 if(at==cb()+0x7f4||at==0x74){*out=stuck?1:0;return 0;}*out=*reg32(at);return 0;}
static int read64(void*c,size_t at,uint64_t*out){(void)c;reads++;assert(at==cb()+0x20||at==cb()+0x28);memcpy(out,(unsigned char*)regs+at,8);return 0;}
static int write32(void*c,size_t at,uint32_t value){(void)c;writes++;assert(at<0x29000||at>=0x2a000);assert(at<0x20000||(at>=cb()&&at<cb()+0x1000));
 if(at==cb()+0x7f0||at==0x70)syncs++;
 if(at==cb()+0x58)*reg32(at)&=~value;else if(at==0)*reg32(at)=value&~dropNs;else if(!(dropTcr&&at==cb()+0x30))*reg32(at)=value;
 if(foreign&&at==cb()){*reg32(0xc00)=21;}return 0;}
static int write64(void*c,size_t at,uint64_t value){(void)c;writes++;assert(at==cb()+0x20||at==cb()+0x28);memcpy((unsigned char*)regs+at,&value,8);return 0;}
static int barrier(void*c){(void)c;return 0;}static int wait(void*c){(void)c;waits++;return 0;}
static ArmSmmu4KConfig config={39,36,0x200000,16};
static ArmSmmu4KResult tables={0x200000,0xff44,3,1,1,0};
static void setup(OSMA_SESSION*s,OSMA_REQUEST*q){memset(regs,0,sizeof(regs));memset(s,0,sizeof(*s));cbreads=writes=reads=syncs=waits=deny=stuck=dropTcr=foreign=dropNs=forcedTcr2=forcedSctlr=0;
 *reg32(0x20)=0x4c017e18;*reg32(0x24)=0x40000016;*reg32(0x28)=0x5511;*reg32(0)=0x00c00406;
 const unsigned sid[4]={0,1,2,5},bank[4]={0,1,9,5};for(unsigned i=0;i<4;i++){*reg32(0x800+4*i)=0x80000000|sid[i];*reg32(0xc00+4*i)=bank[i];}
 *q=(OSMA_REQUEST){0};q->Io=(ArmSmmu4KIo){regs,0x40000,read32,read64,write32,write64,barrier};
 q->Proof=(OSMA_PROOFS){regs,(void*)1,(void*)2,(void*)3,(void*)4,(void*)5,NULL,NULL,19,3,proof};
 q->TableConfig=&config;q->TableResult=&tables;q->Bank=q->Asid=5;q->Slot=3;q->PollBudget=3;q->WaitOneUs=wait;
}
int main(void){unsigned cases=0;OSMA_SESSION s;OSMA_REQUEST q;setup(&s,&q);deny=1;
 assert(OsmaActivate(&s,&q)==OSMA_OWNER&&!writes&&!reads&&s.LastOwnerStatus==-91&&!s.MustRetain);cases++;
 setup(&s,&q);*reg32(0xc00+8)=5; /* Protected SID2 moves to candidate CB5. */
 assert(OsmaActivate(&s,&q)==OSMA_HANDOFF&&!writes);cases++;
 setup(&s,&q);*reg32(cb())=1;assert(OsmaActivate(&s,&q)==OSMA_BANK_BUSY&&!writes);cases++;
 setup(&s,&q);*reg32(0)=0;assert(OsmaActivate(&s,&q)==OSMA_GLOBAL_REQUIRED&&!writes);cases++;
 setup(&s,&q);assert(OsmaActivate(&s,&q)==OSMA_OK&&s.Phase==OSMA_ACTIVE&&s.MustRetain&&s.After.S2cr[3]==0x305);
 assert(*reg32(cb()+0x30)==0x00803519&&*reg32(cb()+0x38)==0xf404ff44&&*reg32(cb())==0x00c00067&&syncs==2);
 unsigned before=writes;assert(OsmaDisableStopped(&s,&q)==OSMA_OWNER&&writes==before);q.Proof.StopSerial=4;
 assert(OsmaDisableStopped(&s,&q)==OSMA_OK&&s.Phase==OSMA_DISABLED&&!s.MustRetain&&!*reg32(cb())&&(*reg32(0xc0c)&0x30000)==0x20000);cases++;
 setup(&s,&q);stuck=1;assert(OsmaActivate(&s,&q)==OSMA_TIMEOUT&&s.Phase==OSMA_POISONED&&s.MustRetain&&syncs==1&&s.Polls==3&&waits==2);
 before=writes;assert(OsmaActivate(&s,&q)==OSMA_ARGUMENT&&writes==before&&syncs==1);cases++;
 setup(&s,&q);dropTcr=1;assert(OsmaActivate(&s,&q)==OSMA_MISMATCH&&s.Phase==OSMA_POISONED&&!*reg32(cb())&&s.MustRetain);cases++;
 setup(&s,&q);*reg32(0)=0;*reg32(0x10)=1u<<26;q.Proof.NsBlock=(void*)6;
 assert(OsmaActivate(&s,&q)==OSMA_OK&&*reg32(0)==0x00c00406&&!(*reg32(0x10)&(1u<<26))&&syncs==3&&s.Before.Nscr0==0&&s.Before.Nsacr==(1u<<26));cases++;
 setup(&s,&q);foreign=1;assert(OsmaActivate(&s,&q)==OSMA_MISMATCH&&s.Phase==OSMA_POISONED&&s.MustRetain);cases++;
 setup(&s,&q);*reg32(0x80c)=0;*reg32(0xc0c)=0;assert(OsmaActivate(&s,&q)==OSMA_OK&&s.After.Smr[3]==0x80000005&&s.After.S2cr[3]==0x305);cases++;
 /* Actual G672 stream-default image, modeled proof producer deliberately
  * absent for the first case: no candidate CB read or store is allowed. */
 setup(&s,&q);*reg32(0)=0x002f0406;*reg32(0x10)=0x1c;for(unsigned i=0;i<OSH_SMRS;i++){*reg32(0x800+4*i)=0;*reg32(0xc00+4*i)=0x20000;}
 assert(OsmaActivate(&s,&q)==OSMA_GLOBAL_REQUIRED&&!writes&&!cbreads&&s.Handoff.Status==OSH_COLD_FAULT_DEFAULT&&s.Handoff.ProtectedBank==UINT32_MAX&&!s.Handoff.ReadEligibleBankMask);cases++;
 setup(&s,&q);*reg32(0)=0x002f0406;*reg32(0x10)=0x1c;for(unsigned i=0;i<OSH_SMRS;i++){*reg32(0x800+4*i)=0;*reg32(0xc00+4*i)=0x20000;}q.Proof.NsBlock=(void*)6;
 assert(OsmaActivate(&s,&q)==OSMA_OK&&s.Handoff.Status==OSH_COLD_FAULT_DEFAULT&&s.After.Smr[3]==0x80000005&&s.After.S2cr[3]==0x305&&s.After.Nscr0&(1u<<10));for(unsigned i=0;i<OSH_SMRS;i++)if(i!=3)assert(s.After.Smr[i]==0&&s.After.S2cr[i]==0x20000);cases++;

 /* G790 actual before/readback; optional RAZ bits cannot be accepted enabled. */
 for(unsigned mode=0;mode<5;mode++){
  setup(&s,&q);*reg32(0)=0x002f0406;*reg32(0x10)=0x1c;
  for(unsigned i=0;i<OSH_SMRS;i++){*reg32(0x800+4*i)=0;*reg32(0xc00+4*i)=0x20000;}
  q.Proof.NsBlock=(void*)6;
  if(mode==0){dropNs=0x1830;assert(OsmaActivate(&s,&q)==OSMA_OK&&s.DesiredNscr0==0x00ef0406&&s.After.Nscr0==0x00ef0406);}
  else if(mode==1){*reg32(0)|=0x1830;assert(OsmaActivate(&s,&q)==OSMA_HANDOFF&&!writes);}
  else {dropNs=mode==2?2u:mode==3?4u:0x400u;assert(OsmaActivate(&s,&q)==OSMA_MISMATCH&&s.MustRetain&&s.After.Nscr0==(0x00ef0406&~dropNs));}
  cases++;
 }

 /* G798 explicit TBI policy, not readback masking or a RES1 assumption. */
 for(unsigned mode=0;mode<4;mode++){
  setup(&s,&q);*reg32(0)=0x002f0406;*reg32(0x10)=0x1c;
  for(unsigned i=0;i<OSH_SMRS;i++){*reg32(0x800+4*i)=0;*reg32(0xc00+4*i)=0x20000;}
  q.Proof.NsBlock=(void*)6;forcedTcr2=mode==0?0x38071:mode==1?0x38011:mode==2?0x38031:0x38070;
  if(mode==0){assert(OsmaActivate(&s,&q)==OSMA_OK&&s.Image.tcr2==0x38071&&s.Readback.tcr2==0x38071);assert(s.Image.tcr&0x800000);assert((s.Image.ttbr1&0x0000ffffffffffffull)==0);}
  else {assert(OsmaActivate(&s,&q)==OSMA_MISMATCH&&s.MustRetain&&s.Readback.tcr2==forcedTcr2&&s.Readback.sctlr==0);}
  cases++;
 }

 /* G810 optional private-ASID hint omitted, real ASID tags retained. */
 for(unsigned mode=0;mode<4;mode++){
  setup(&s,&q);*reg32(0)=0x002f0406;*reg32(0x10)=0x1c;
  for(unsigned i=0;i<OSH_SMRS;i++){*reg32(0x800+4*i)=0;*reg32(0xc00+4*i)=0x20000;}
  q.Proof.NsBlock=(void*)6;forcedSctlr=mode==0?0x00c00067:mode==1?0x00c01067:mode==2?0x00c00066:0x00c00027;
  if(mode==0){assert(OsmaActivate(&s,&q)==OSMA_OK&&s.Image.sctlr==0x00c00067&&s.Readback.sctlr==0x00c00067);assert((s.Image.ttbr0>>48)==q.Asid&&(s.Image.ttbr1>>48)==q.Asid);assert((s.Image.ttbr1&0x0000ffffffffffffull)==0&&s.Image.tcr2==0x38071&&s.DesiredNscr0==0x00ef0406);}
  else{assert(OsmaActivate(&s,&q)==OSMA_MISMATCH&&s.MustRetain&&s.Readback.sctlr==forcedSctlr);}
  cases++;
 }
 printf("{\"cases\":%u,\"native\":false,\"result\":\"pass\"}\n",cases);
}
