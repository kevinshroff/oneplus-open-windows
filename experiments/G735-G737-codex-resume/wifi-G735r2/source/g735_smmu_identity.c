/* SPDX-License-Identifier: MIT
 * Exclusive one-boot diagnostic allocation. Never reassign a valid SMR or
 * a referenced/nonzero CB. No rollback after partial writes: withhold PCI
 * publication and retain this state until reset. Caller gates every write.
 */
#include "g735_smmu_identity.h"
#define CB_CBAR 0x0001f000u
#define CB_CBA2R 1u
#define CB_SCTLR 0xe0u
static int fail(G735_RESULT*r,uint32_t stage,uint32_t code){r->Stage=stage;r->Code=code;return (int)code;}
void G735Init(G735_RESULT*r){
 unsigned char*p=(unsigned char*)r;
 for(size_t n=0;n<sizeof(*r);n++)p[n]=0;
 r->Magic=0x35333747u;r->Version=2;r->Bytes=sizeof(*r);
 r->Stream[0].Sid=0x1401;r->Stream[1].Sid=0x1400;
}
int G735Geometry(uint32_t id0,uint32_t id1,G735_RESULT*r){
 r->Id0=id0;r->Id1=id1;r->NumSmr=id0&0xff;r->NumCb=id1&0xff;
 r->PageSize=(id1&(1u<<31))?0x10000u:0x1000u;
 r->Pages=1u<<(((id1>>28)&7)+1);
 r->CbBase=G735_BASE+(uint64_t)r->Pages*r->PageSize;
 uint64_t span=(uint64_t)(r->Pages+r->NumCb)*r->PageSize;
 /* Require stream matching and stage-1 support. EXIDS needs different valid
  * encoding; do not silently treat it as the legacy SMR VALID mechanism. */
 if(!(id0&(1u<<27))||!(id0&(1u<<30))||(id0&(1u<<8))||
    !r->NumSmr||r->NumSmr>G735_MAX_SMR||!r->NumCb||
    span>G735_APERTURE)return fail(r,1,2);
 r->Span=(uint32_t)span;return 0;
}
static int rd(const G403_IO*i,uint64_t a,uint32_t*v){return i->Read32(i->Context,a,v);}
static int put(const G403_IO*i,G735_RESULT*r,uint64_t a,uint32_t v){
 r->LastAddress=a;r->LastExpected=v;r->LastReadbackValid=0;r->AttemptedWrites++;r->RetainUntilReset=1;
 if(i->Write32(i->Context,a,v))return 1;
 r->Writes++;r->RetainUntilReset=1;
 if(rd(i,a,&r->LastReadback))return 1;
 r->LastReadbackValid=1;
 return r->LastReadback!=v;
}
static int overlaps(uint32_t smr,uint32_t sid){
 uint32_t mask=(smr>>16)&0x7fff;
 return smr&&!(((smr&0x7fff)^sid)&~mask&0x7fff);
}
static const uint32_t cb_regs[]={0,4,0x10,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,0x58};
static int untouched(const G403_IO*i,G735_RESULT*r,uint32_t cb){
 uint32_t v;uint64_t base=r->CbBase+(uint64_t)cb*r->PageSize;
 for(size_t n=0;n<sizeof(cb_regs)/sizeof(cb_regs[0]);n++){
  if(rd(i,base+cb_regs[n],&v))return -1;
  if(v)return 0;
 }
 if(rd(i,G735_BASE+r->PageSize+4*cb,&v))return -1;
 if(v)return 0;
 if(rd(i,G735_BASE+r->PageSize+0x800+4*cb,&v))return -1;
 return v?0:1;
}
int G735PrepareIdentity(const G403_IO*i,G735_RESULT*r){
 uint32_t id0,id1,smr[G735_MAX_SMR],s2cr[G735_MAX_SMR];
 uint8_t used[G735_MAX_CB]={0};uint32_t slots[2],banks[2],ns=0,nb=0;
 if(!i||!i->Read32||!i->Write32||!r)return 1;
 if(r->Prepared||r->AttemptedWrites)return fail(r,0,2);
 if(rd(i,G735_BASE+0x20,&id0)||rd(i,G735_BASE+0x24,&id1))return fail(r,1,1);
 if(G735Geometry(id0,id1,r))return (int)r->Code;
 if(rd(i,G735_BASE,&r->Cr0))return fail(r,1,3);
 if(rd(i,G735_BASE+0x48,&r->GfsrBefore)||rd(i,G735_BASE+0x50,&r->Gfsynr0Before)||rd(i,G735_BASE+0x54,&r->Gfsynr1Before))return fail(r,1,5);
 if(r->GfsrBefore)return fail(r,1,6);
 if(r->Cr0&1u)return fail(r,1,4); /* CLIENTPD: no global-state mutation */
 /* Scan the complete supported SMR inventory before any write. Even a
  * broad/masked pre-existing or staged match is owned by someone else: refuse it. */
 for(uint32_t n=0;n<r->NumSmr;n++){
  if(rd(i,G735_BASE+0x800+4*n,&smr[n])||rd(i,G735_BASE+0xc00+4*n,&s2cr[n]))return fail(r,2,1);
  r->BeforeSmr[n]=smr[n];r->BeforeS2cr[n]=s2cr[n];r->InventoryCount=n+1;
  if(overlaps(smr[n],0x1400)||overlaps(smr[n],0x1401))return fail(r,2,2);
  /* A staged type-0 S2CR reserves its CB even while SMR VALID is clear.
   * Never borrow a bank out from under a not-yet-enabled stream. */
  if(((s2cr[n]>>16)&3)==0){uint32_t cb=s2cr[n]&0xff;if(cb>=r->NumCb)return fail(r,2,3);used[cb]=1;}
  if(!smr[n]&&s2cr[n]==0x00020000u&&ns<2)slots[ns++]=n;
 }
 if(ns!=2)return fail(r,2,4);
 /* Keep CB0 out of the allocator even when it looks idle. All selected CB
  * configuration/fault state must be zero, not just SCTLR.M. */
 for(uint32_t cb=1;cb<r->NumCb&&nb<2;cb++)if(!used[cb]){
  int u=untouched(i,r,cb);if(u<0)return fail(r,2,5);if(u)banks[nb++]=cb;
 }
 if(nb!=2)return fail(r,2,6);
 for(uint32_t k=0;k<2;k++){
  G735_STREAM*s=&r->Stream[k];s->Slot=slots[k];s->Cb=banks[k];
  s->CbAddress=r->CbBase+(uint64_t)s->Cb*r->PageSize;
  s->SmrAddress=G735_BASE+0x800+4*s->Slot;s->S2crAddress=G735_BASE+0xc00+4*s->Slot;
  s->CbarAddress=G735_BASE+r->PageSize+4*s->Cb;
  s->Cba2rAddress=G735_BASE+r->PageSize+0x800+4*s->Cb;
 }
 /* Recheck allocation snapshots before the first write. Caller must hold
  * its physical cold/no-consumer gate throughout (not an OS runtime API). */
 for(uint32_t n=0;n<r->NumSmr;n++){
  uint32_t a,b;if(rd(i,G735_BASE+0x800+4*n,&a)||rd(i,G735_BASE+0xc00+4*n,&b)||a!=smr[n]||b!=s2cr[n])return fail(r,3,1);
 }
 for(uint32_t k=0;k<2;k++)if(untouched(i,r,banks[k])!=1)return fail(r,3,2);
 r->PreflightVerified=1;
 for(uint32_t k=0;k<2;k++){
  G735_STREAM*s=&r->Stream[k];uint32_t v;
  /* Zero state was verified; configure CBAR/CBA2R before SCTLR, then link
   * S2CR to that exact bank. Make the SMR valid last. */
  if(put(i,r,s->Cba2rAddress,CB_CBA2R)||put(i,r,s->CbarAddress,CB_CBAR)||
     put(i,r,s->CbAddress,CB_SCTLR))return fail(r,4,1);
  if(put(i,r,s->S2crAddress,s->Cb))return fail(r,4,2);
  if(rd(i,s->SmrAddress,&v)||v!=smr[s->Slot])return fail(r,4,3);
  if(put(i,r,s->SmrAddress,0x80000000u|s->Sid))return fail(r,4,4);
 }
 /* TLB sync is completion-only, not a TLB invalidation or a DMA proof. */
 r->LastAddress=G735_BASE+0x70;r->LastExpected=0;r->LastReadbackValid=0;r->AttemptedWrites++;r->RetainUntilReset=1;
 if(i->Write32(i->Context,G735_BASE+0x70,0))return fail(r,5,1);
 r->Writes++;
 uint32_t n,v=1;
 for(n=0;n<100000;n++){if(rd(i,G735_BASE+0x74,&v))return fail(r,5,2);if(!(v&1))break;}
 if(v&1)return fail(r,5,3);
 for(uint32_t k=0;k<2;k++){
  G735_STREAM*s=&r->Stream[k];
  if(rd(i,s->SmrAddress,&s->Smr)||rd(i,s->S2crAddress,&s->S2cr)||
     rd(i,s->CbAddress,&s->Sctlr)||rd(i,s->CbarAddress,&s->Cbar)||rd(i,s->Cba2rAddress,&s->Cba2r))return fail(r,6,1);
  if(s->Smr!=(0x80000000u|s->Sid)||s->S2cr!=s->Cb||s->Sctlr!=CB_SCTLR||s->Cbar!=CB_CBAR||s->Cba2r!=CB_CBA2R)return fail(r,6,2);
 }
 if(rd(i,G735_BASE+0x48,&r->GfsrAfter)||r->GfsrAfter)return fail(r,6,3);
 r->Prepared=1;r->Stage=7;r->Code=0;return 0;
}
