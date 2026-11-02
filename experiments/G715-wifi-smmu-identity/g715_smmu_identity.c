/* SPDX-License-Identifier: MIT */
#include "g715_smmu_identity.h"
#define SMMU UINT64_C(0x15000000)
#define SMMU_LEN 0x100000u
#define SID_ROOT 0x1400u
#define SID_EP 0x1401u
#define CB_CBAR 0x0001f000u /* S1_TRANS_S2_FAULT + S1_MEMATTR WB: UEFI bank clone */
#define CB_CBA2R 0x00000001u /* VA64 */
#define CB_SCTLR 0x000000e0u /* CFCFG|CFIE|CFRE; M=0 => identity pass-through */
static int fail(G715_RESULT*r,uint32_t stage,uint32_t code){if(r){r->Stage=stage;r->Code=code;}return (int)code;}
static int rd(const G403_IO*i,uint64_t a,uint32_t*v){return i->Read32(i->Context,a,v);}
static int wr(const G403_IO*i,uint64_t a,uint32_t v){return i->Write32(i->Context,a,v);}
/* Find a valid SMR whose ID exactly equals sid (reuse), else the lowest
 * invalid SMR slot; -1 none, -2 io error. */
static int find_slot(const G403_IO*i,uint32_t sid,uint32_t nsmr){
 int free_slot=-1;
 for(uint32_t n=0;n<nsmr&&n<128;n++){
  uint32_t smr;
  if(rd(i,SMMU+0x800+4*n,&smr))return -2;
  if((smr>>31)&&((smr&0xffff)==sid))return (int)n;
  if(!(smr>>31)&&free_slot<0)free_slot=(int)n;
 }
 return free_slot;
}
/* Lowest context bank not referenced by any valid translate S2CR, not the
 * excluded index, in aperture, whose SCTLR is untouched (0); -1/-2 as above. */
static int find_cb(const G403_IO*i,uint32_t nsmr,uint32_t ncb,uint32_t pages,uint32_t psize,int exclude){
 uint64_t used=0;
 for(uint32_t n=0;n<nsmr&&n<128;n++){
  uint32_t smr,s2cr;
  if(rd(i,SMMU+0x800+4*n,&smr)||rd(i,SMMU+0xc00+4*n,&s2cr))return -2;
  if((smr>>31)&&(((s2cr>>16)&3)==0))used|=(uint64_t)1<<(s2cr&0x3f);
 }
 for(uint32_t n=1;n<ncb&&n<64;n++){
  uint32_t sctlr;
  if((int)n==exclude||(used>>n)&1)continue;
  if((uint32_t)((pages+n+1)*psize)>SMMU_LEN)return -1;
  if(rd(i,SMMU+(uint64_t)(pages+n+1)*psize,&sctlr))return -2;
  if(!sctlr)return (int)n;
 }
 return -1;
}
static int program_stream(const G403_IO*i,uint32_t sid,uint32_t slot,uint32_t cb,G715_RESULT*r){
 uint64_t cbp=SMMU+(uint64_t)(r->Pages+cb+1)*r->PageSize;
 uint64_t gr1=SMMU+r->PageSize;
 uint32_t v;
 /* 1) identity bank: clear stale fault, zero stage-1 state, clone UEFI bank
  *    style, SCTLR last. */
 if(wr(i,cbp+0x58,0xffffffffu)||rd(i,cbp+0x58,&v)||v)return fail(r,3,1);
 if(wr(i,cbp+0x20,0)||wr(i,cbp+0x24,0)||wr(i,cbp+0x30,0)||wr(i,cbp+0x10,0)||
    wr(i,cbp+0x38,0)||wr(i,cbp+0x3c,0))return fail(r,3,2);
 if(wr(i,gr1+0x800+4*cb,CB_CBA2R)||rd(i,gr1+0x800+4*cb,&v)||v!=CB_CBA2R)return fail(r,3,3);
 if(wr(i,gr1+4*cb,CB_CBAR)||rd(i,gr1+4*cb,&v)||v!=CB_CBAR)return fail(r,3,4);
 if(wr(i,cbp,CB_SCTLR)||rd(i,cbp,&v)||v!=CB_SCTLR)return fail(r,3,5);
 r->Writes+=8;
 /* 2) stream match: S2CR type0 translate -> cb (cbndx<<2), SMR valid last. */
 if(wr(i,SMMU+0xc00+4*slot,cb<<2)||rd(i,SMMU+0xc00+4*slot,&v)||v!=(cb<<2))return fail(r,4,1);
 if(wr(i,SMMU+0x800+4*slot,0x80000000u|sid)||rd(i,SMMU+0x800+4*slot,&v)||v!=(0x80000000u|sid))return fail(r,4,2);
 r->Writes+=2;
 /* 3) sTLB sync + final readback. */
 if(wr(i,SMMU+0x70,0))return fail(r,5,1);
 for(uint32_t n=0;n<100000;n++){
  uint32_t s;
  if(rd(i,SMMU+0x74,&s))return fail(r,5,2);
  if(!(s&1))break;
  if(n==99999)return fail(r,5,3);
 }
 if(rd(i,SMMU+0x800+4*slot,&v)||v!=(0x80000000u|sid))return fail(r,5,4);
 if(rd(i,SMMU+0xc00+4*slot,&v)||v!=(cb<<2))return fail(r,5,5);
 if(rd(i,cbp,&v)||v!=CB_SCTLR)return fail(r,5,6);
 return 0;
}
int G715PrepareIdentity(const G403_IO*i,G715_RESULT*r){
 if(!i||!i->Read32||!i->Write32||!r)return fail(0,0,1);
 if(r->Prepared)return fail(r,0,2);
 if(rd(i,SMMU+0x20,&r->Id0)||rd(i,SMMU+0x24,&r->Id1))return fail(r,1,1);
 r->NumSmr=r->Id0&0xff;
 r->NumCb=r->Id1&0xff;
 r->PageSize=(r->Id1&(1u<<31))?0x10000u:0x1000u;
 r->Pages=1u<<(((r->Id1>>28)&7)+1);
 if(!r->NumSmr||!r->NumCb||r->NumSmr>128||r->NumCb>64)return fail(r,1,2);
 int s_ep=find_slot(i,SID_EP,r->NumSmr);
 if(s_ep==-2)return fail(r,2,1);
 int c_ep=find_cb(i,r->NumSmr,r->NumCb,r->Pages,r->PageSize,-1);
 if(c_ep==-2)return fail(r,2,2);
 if(c_ep==-1||s_ep==-1)return fail(r,2,3);
 r->SlotEp=(uint32_t)s_ep;r->CbEp=(uint32_t)c_ep;
 int e=program_stream(i,SID_EP,r->SlotEp,r->CbEp,r);
 if(e)return e;
 int s_root=find_slot(i,SID_ROOT,r->NumSmr);
 if(s_root==-2)return fail(r,6,1);
 if(s_root<0){r->Prepared=1;return 0;} /* endpoint stream is the DMA path */
 int c_root=find_cb(i,r->NumSmr,r->NumCb,r->Pages,r->PageSize,(int)r->CbEp);
 if(c_root==-2)return fail(r,6,2);
 if(c_root==-1)c_root=(int)r->CbEp; /* distinct untouched bank preferred, shared is valid */
 r->SlotRoot=(uint32_t)s_root;r->CbRoot=(uint32_t)c_root;
 e=program_stream(i,SID_ROOT,r->SlotRoot,r->CbRoot,r);
 if(e)return e;
 r->Prepared=1;r->Code=0;
 return 0;
}
