/* SPDX-License-Identifier: MIT */
#include "open_smmu_handoff.h"
#include <string.h>
static int Overlap(const void*a,unsigned an,const void*b,unsigned bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x>UINTPTR_MAX-an||y>UINTPTR_MAX-bn||(x<y+bn&&y<x+an);}
static const uint32_t Sids[OSH_ROLES]={0,1,4,5,7,2};
static int Valid(uint32_t s){return (s>>31)!=0;}
static uint32_t Id(uint32_t s){return s&0x7fffu;}
static uint32_t Mask(uint32_t s){return (s>>16)&0x7fffu;}
static int Match(uint32_t s,uint32_t sid){return ((Id(s)^sid)&~Mask(s)&0x7fffu)==0;}
static int Intersect(uint32_t a,uint32_t b){return ((Id(a)^Id(b))&~(Mask(a)|Mask(b))&0x7fffu)==0;}
static enum osh_status Fail(OSH_REPORT*r,enum osh_status e){r->ReadEligibleBankMask=0;for(unsigned j=0;j<OSH_ROLES;j++)r->Route[j].ReadEligible=0;return r->Status=e;}
enum osh_status OshAnalyze(const OSH_SNAPSHOT*a,const OSH_SNAPSHOT*b,OSH_REPORT*r){
 if(!r||!a||!b||Overlap(a,sizeof(*a),b,sizeof(*b))||Overlap(a,sizeof(*a),r,sizeof(*r))||Overlap(b,sizeof(*b),r,sizeof(*r)))return OSH_ARGUMENT;memset(r,0,sizeof(*r));r->ProtectedBank=r->AliasA=r->AliasB=UINT32_MAX;
 for(unsigned j=0;j<OSH_ROLES;j++){r->Route[j].Sid=Sids[j];r->Route[j].Index=r->Route[j].Bank=UINT32_MAX;}
 if(!a||!b)return Fail(r,OSH_ARGUMENT);
 /* Narrow observed Open profile: no EXIDS, 15-bit SID match, native4K,
  * 24 stream slots,22 banks and CB offset20000. No guessed dynamic walk. */
 if(a->Id0!=0x4c017e18u||a->Id1!=0x40000016u||a->Id2!=0x5511u)return Fail(r,OSH_PROFILE);
 if(memcmp(a,b,sizeof(*a)))return Fail(r,OSH_UNSTABLE);r->Stable=1;
 if(a->Nscr0==UINT32_MAX||a->Nsacr==UINT32_MAX||(a->Nscr0&(1u<<3)))return Fail(r,OSH_PROFILE);
 for(unsigned i=0;i<OSH_SMRS;i++){
  uint32_t s=a->Smr[i],v=a->S2cr[i];
  if(s==UINT32_MAX||v==UINT32_MAX)return Fail(r,OSH_PROFILE);
  if(!Valid(s))continue;
  /* Bit15 is outside this profile's15-bit ID; bit31 is VALID, not MASK15.
   * Reject reserved/EXID fields before relying on any route. */
  if((s&0x8000u)||(v&~0x030303ffu)||((v>>16)&3u)==3u)return Fail(r,OSH_ROUTE);
  if(((v>>16)&3u)==0&&(v&255u)>=OSH_BANKS)return Fail(r,OSH_ROUTE);
  for(unsigned k=0;k<i;k++)if(Valid(a->Smr[k])&&Intersect(s,a->Smr[k])){
   r->AliasA=k;r->AliasB=i;return Fail(r,OSH_ALIAS);
  }
  for(unsigned j=0;j<OSH_ROLES;j++)if(Match(s,Sids[j])){
   OSH_ROUTE_INFO*q=&r->Route[j];q->Found++;q->Index=i;q->Bank=v&255u;q->Type=(v>>16)&3u;q->Mask=Mask(s);
  }
 }
 /* Native G672 cold profile: invalid SMRs and fault S2CR defaults do not
  * identify a protected CB. USFCFG must fault unmatched SID2 as well. This
  * recognizes current observations only; it never allocates any CB/ASID. */
 unsigned cold=(a->Nscr0&(1u<<10))!=0;
 for(unsigned i=0;i<OSH_SMRS;i++)if(a->Smr[i]!=0||a->S2cr[i]!=0x20000u)cold=0;
 if(cold)return r->Status=OSH_COLD_FAULT_DEFAULT;
 OSH_ROUTE_INFO*protectedRoute=&r->Route[5];
 /* Missing/masked/bypass protected route does NOT prove a bank is free.
  * Preserve all CBs in that case; still return the actual global observations. */
 if(protectedRoute->Found!=1||protectedRoute->Mask||protectedRoute->Type!=0)
  return Fail(r,OSH_PROTECTED_UNKNOWN);
 r->ProtectedBank=protectedRoute->Bank;
 for(unsigned j=0;j<OSH_ROLES;j++){
  OSH_ROUTE_INFO*q=&r->Route[j];
  if(q->Sid!=0&&q->Sid!=1&&q->Sid!=5)continue;
  if(q->Found!=1||q->Mask||q->Type!=0||q->Bank==r->ProtectedBank)continue;
  unsigned users=0;
  for(unsigned i=0;i<OSH_SMRS;i++)if(Valid(a->Smr[i])&&((a->S2cr[i]>>16)&3u)==0&&(a->S2cr[i]&255u)==q->Bank)users++;
  if(users!=1)continue; /* No shared/foreign/masked stream alias to this CB. */
  q->ReadEligible=1;r->ReadEligibleBankMask|=1u<<q->Bank;
 }
 /* This is read eligibility only; no CB is read by this core, no ownership
  * token, translation readiness, global-write permission or stop proof. */
 return r->Status=OSH_OK;
}
