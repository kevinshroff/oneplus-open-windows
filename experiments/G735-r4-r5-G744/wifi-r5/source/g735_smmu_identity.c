/* SPDX-License-Identifier: MIT
 * Observed SM8550 inactive-bank diagnostic allocator. Unreferenced does not
 * prove absence of a secure-world reservation. Before every attempted write,
 * recheck all stream bindings and both selected banks against the snapshots
 * advanced only after a verified owned write. Caller separately proves the
 * namespace/BME/cold physical gate immediately before the hardware store.
 * No fault clear, ACTLR write, global-state mutation, retry or rollback.
 */
#include "g735_smmu_identity.h"
#define CB_CBAR 0x0001f000u
#define CB_CBA2R 1u
#define CB_SCTLR 0xe0u
#define FSR_FORMAT_AARCH64 0x400u
static int fail(G735_RESULT*r,uint32_t stage,uint32_t code){r->Stage=stage;r->Code=code;return (int)code;}
void G735Init(G735_RESULT*r){
 unsigned char*p=(unsigned char*)r;for(size_t n=0;n<sizeof(*r);n++)p[n]=0;
 r->Magic=0x35333747u;r->Version=5;r->Bytes=sizeof(*r);
 r->Stream[0].Sid=0x1401;r->Stream[1].Sid=0x1400;
}
int G735Geometry(uint32_t id0,uint32_t id1,G735_RESULT*r){
 r->Id0=id0;r->Id1=id1;r->NumSmr=id0&0xff;r->NumCb=id1&0xff;
 r->PageSize=(id1&(1u<<31))?0x10000u:0x1000u;r->Pages=1u<<(((id1>>28)&7)+1);
 r->CbBase=G735_BASE+(uint64_t)r->Pages*r->PageSize;
 uint64_t span=(uint64_t)(r->Pages+r->NumCb)*r->PageSize;
 if(!(id0&(1u<<27))||!(id0&(1u<<30))||(id0&(1u<<8))||!r->NumSmr||
    r->NumSmr>G735_MAX_SMR||!r->NumCb||span>G735_APERTURE)return fail(r,1,2);
 r->Span=(uint32_t)span;return 0;
}
static int rd(const G403_IO*i,uint64_t a,uint32_t*v){return i->Read32(i->Context,a,v);}
static int overlaps(uint32_t smr,uint32_t sid){uint32_t mask=(smr>>16)&0x7fff;return smr&&!(((smr&0x7fff)^sid)&~mask&0x7fff);}
static const uint32_t cb_regs[]={0,4,0x10,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,0x58};
_Static_assert(sizeof(G735_BANK)==14*sizeof(uint32_t),"bank report ABI");
static void addresses(G735_RESULT*r,G735_STREAM*s,uint32_t slot,uint32_t cb){
 s->Slot=slot;s->Cb=cb;s->CbAddress=r->CbBase+(uint64_t)cb*r->PageSize;
 s->SmrAddress=G735_BASE+0x800+4*slot;s->S2crAddress=G735_BASE+0xc00+4*slot;
 s->CbarAddress=G735_BASE+r->PageSize+4*cb;s->Cba2rAddress=G735_BASE+r->PageSize+0x800+4*cb;
}
static int bank_read(const G403_IO*i,const G735_STREAM*s,G735_BANK*b){
 uint32_t*v=b->Word;
 for(size_t n=0;n<12;n++)if(rd(i,s->CbAddress+cb_regs[n],&v[n]))return 1;
 return rd(i,s->CbarAddress,&b->Cbar)||rd(i,s->Cba2rAddress,&b->Cba2r);
}
static int equal_bank(const G735_BANK*a,const G735_BANK*b){
 const uint32_t*x=a->Word,*y=b->Word;
 for(size_t n=0;n<14;n++)if(x[n]!=y[n])return 0;return 1;
}
static int inactive_profile(const G735_BANK*b){
 /* Other configuration fields are UNKNOWN/uninitialized, not ownership
  * evidence. They are snapshotted and explicitly overwritten while unused.
  * ACTLR=3 is observed hardware cache policy and is never modified. */
 return !(b->Sctlr&(1u|(1u<<5)|(1u<<6)))&&b->Actlr==3&&
        !b->Fsr&&!b->Cbar&&!b->Cba2r;
}
typedef struct {
 uint32_t Smr[G735_MAX_SMR],S2cr[G735_MAX_SMR];G735_BANK Bank[2];
} EXPECTED;
static void after_bank(const G403_IO*i,G735_STREAM*s){
 s->AfterValid=0;
 if(s->BeforeValid&&!bank_read(i,s,&s->After)){
  s->AfterValid=1;s->Sctlr=s->After.Sctlr;s->Cbar=s->After.Cbar;s->Cba2r=s->After.Cba2r;
 }
}
static void capture_after(const G403_IO*i,G735_RESULT*r){
 for(unsigned k=0;k<2;k++){G735_STREAM*s=&r->Stream[k];after_bank(i,s);
  s->SmrReadValid=!rd(i,s->SmrAddress,&s->Smr);
  s->S2crReadValid=!rd(i,s->S2crAddress,&s->S2cr);
 }
}
static int current(const G403_IO*i,G735_RESULT*r,const EXPECTED*e){
 uint32_t v;int mismatch=0;r->Revalidations++;
 if(rd(i,G735_BASE,&v)||v!=r->Cr0||rd(i,G735_BASE+0x20,&v)||v!=r->Id0||
    rd(i,G735_BASE+0x24,&v)||v!=r->Id1)mismatch=1;
 if(rd(i,G735_BASE+0x48,&r->GfsrAfter)||r->GfsrAfter)mismatch=1;
 for(uint32_t n=0;n<r->NumSmr;n++){
  uint32_t a=0,b=0;int ea=rd(i,G735_BASE+0x800+4*n,&a),eb=rd(i,G735_BASE+0xc00+4*n,&b);
  if(ea||eb||a!=e->Smr[n]||b!=e->S2cr[n])mismatch=1;
  for(unsigned k=0;k<2;k++)if(r->Stream[k].Slot==n){G735_STREAM*s=&r->Stream[k];
   s->SmrReadValid=!ea;s->S2crReadValid=!eb;if(!ea)s->Smr=a;if(!eb)s->S2cr=b;
  }
 }
 for(unsigned k=0;k<2;k++){G735_STREAM*s=&r->Stream[k];after_bank(i,s);
  if(!s->AfterValid||!equal_bank(&s->After,&e->Bank[k]))mismatch=1;
 }
 return mismatch;
}
static int advance(EXPECTED*e,const G735_RESULT*r,uint64_t a,uint32_t v){
 for(unsigned k=0;k<2;k++){
  const G735_STREAM*s=&r->Stream[k];uint32_t*b=e->Bank[k].Word;
  if(a==s->SmrAddress){e->Smr[s->Slot]=v;return 0;}
  if(a==s->S2crAddress){e->S2cr[s->Slot]=v;return 0;}
  if(a==s->CbarAddress){e->Bank[k].Cbar=v;return 0;}
  if(a==s->Cba2rAddress){
   /* IHI0062D.c 16.5.9: read-only FSR.Format is generated from VA64.
    * Only the exact owned AArch64 selection has this derived side effect.
    * Never clear/write FSR or mask faults; next full snapshot must be 0x400. */
   if(v!=CB_CBA2R)return 1;
   e->Bank[k].Cba2r=v;e->Bank[k].Fsr=FSR_FORMAT_AARCH64;return 0;
  }
  for(unsigned n=0;n<12;n++)if(a==s->CbAddress+cb_regs[n]&&n!=1&&n!=11){b[n]=v;return 0;}
 }
 return 1;
}
static int put(const G403_IO*i,G735_RESULT*r,EXPECTED*e,uint64_t a,uint32_t v){
 if(current(i,r,e))return 1;
 r->LastAddress=a;r->LastExpected=v;r->LastReadbackValid=0;
 r->AttemptedWrites++;r->RetainUntilReset=1;
 if(i->Write32(i->Context,a,v)){capture_after(i,r);return 1;}
 r->Writes++;
 if(rd(i,a,&r->LastReadback)){capture_after(i,r);return 1;}
 r->LastReadbackValid=1;
 if(r->LastReadback!=v||advance(e,r,a,v)){capture_after(i,r);return 1;}
 return 0;
}
int G735PrepareIdentity(const G403_IO*i,G735_RESULT*r){
 uint32_t id0,id1;EXPECTED e;uint8_t used[G735_MAX_CB]={0};uint32_t slots[2],ns=0,nb=0;
 if(!i||!i->Read32||!i->Write32||!r)return 1;
 if(r->Prepared||r->AttemptedWrites)return fail(r,0,2);
 if(rd(i,G735_BASE+0x20,&id0)||rd(i,G735_BASE+0x24,&id1))return fail(r,1,1);
 if(G735Geometry(id0,id1,r))return (int)r->Code;
 /* This revision's inactive-bank policy is qualified only by the observed
  * SM8550 register geometry; no generic reset-value assumptions. */
 if(id0!=0x4c017e69u||id1!=0x60000046u)return fail(r,1,7);
 if(rd(i,G735_BASE,&r->Cr0))return fail(r,1,3);
 if(rd(i,G735_BASE+0x48,&r->GfsrBefore)||rd(i,G735_BASE+0x50,&r->Gfsynr0Before)||rd(i,G735_BASE+0x54,&r->Gfsynr1Before))return fail(r,1,5);
 if(r->GfsrBefore)return fail(r,1,6);if(r->Cr0&1u)return fail(r,1,4);
 for(uint32_t n=0;n<r->NumSmr;n++){
  if(rd(i,G735_BASE+0x800+4*n,&e.Smr[n])||rd(i,G735_BASE+0xc00+4*n,&e.S2cr[n]))return fail(r,2,1);
  r->BeforeSmr[n]=e.Smr[n];r->BeforeS2cr[n]=e.S2cr[n];r->InventoryCount=n+1;
  if(overlaps(e.Smr[n],0x1400)||overlaps(e.Smr[n],0x1401))return fail(r,2,2);
  if(((e.S2cr[n]>>16)&3)==0){uint32_t cb=e.S2cr[n]&0xff;if(cb>=r->NumCb)return fail(r,2,3);used[cb]=1;}
  if(!e.Smr[n]&&e.S2cr[n]==0x00020000u&&ns<2)slots[ns++]=n;
 }
 if(ns!=2)return fail(r,2,4);
 for(uint32_t cb=1;cb<r->NumCb&&nb<2;cb++)if(!used[cb]){
  G735_STREAM probe={0};G735_BANK b;addresses(r,&probe,slots[nb],cb);
  if(bank_read(i,&probe,&b))return fail(r,2,5);
  if(inactive_profile(&b)){
   G735_STREAM*s=&r->Stream[nb];addresses(r,s,slots[nb],cb);
   s->Before=b;s->BeforeValid=1;s->After=b;s->AfterValid=1;e.Bank[nb]=b;nb++;
  }
 }
 if(nb!=2)return fail(r,2,6);
 if(current(i,r,&e))return fail(r,3,1);r->PreflightVerified=1;
 for(unsigned k=0;k<2;k++){
  G735_STREAM*s=&r->Stream[k];
  /* Disable first, then select the intended stage-1/AArch64 register format
   * while streams remain default FAULT and SMR invalid. Offset 0x10 is
   * reserved in the stage-2 format; do not initialize it in that format.
   * TCR2 stays exactly zero: bits 6:5 are TBI1/TBI0, not RES1.
   * ACTLR and FSR remain untouched; no masked readback acceptance. */
  if(put(i,r,&e,s->CbAddress,0))return fail(r,4,1);
  if(put(i,r,&e,s->Cba2rAddress,CB_CBA2R)||put(i,r,&e,s->CbarAddress,CB_CBAR))return fail(r,4,3);
  for(unsigned n=2;n<11;n++)if(put(i,r,&e,s->CbAddress+cb_regs[n],0))return fail(r,4,2);
  if(put(i,r,&e,s->CbAddress,CB_SCTLR))return fail(r,4,3);
  if(put(i,r,&e,s->S2crAddress,s->Cb))return fail(r,4,4);
  if(put(i,r,&e,s->SmrAddress,0x80000000u|s->Sid))return fail(r,4,5);
 }
 /* Sync is completion-only, not a DMA or TLB invalidation certificate. */
 if(current(i,r,&e))return fail(r,5,1);
 r->LastAddress=G735_BASE+0x70;r->LastExpected=0;r->LastReadbackValid=0;
 r->AttemptedWrites++;r->RetainUntilReset=1;
 if(i->Write32(i->Context,G735_BASE+0x70,0)){capture_after(i,r);return fail(r,5,2);}r->Writes++;
 uint32_t n,v=1;for(n=0;n<100000;n++){if(rd(i,G735_BASE+0x74,&v))return fail(r,5,3);if(!(v&1))break;}
 if(v&1)return fail(r,5,4);
 if(current(i,r,&e))return fail(r,6,1);
 for(unsigned k=0;k<2;k++){
  G735_STREAM*s=&r->Stream[k];s->Smr=e.Smr[s->Slot];s->S2cr=e.S2cr[s->Slot];
  s->Sctlr=s->After.Sctlr;s->Cbar=s->After.Cbar;s->Cba2r=s->After.Cba2r;
 }
 if(rd(i,G735_BASE+0x48,&r->GfsrAfter)||r->GfsrAfter)return fail(r,6,2);
 r->Prepared=1;r->Stage=7;r->Code=0;return 0;
}
