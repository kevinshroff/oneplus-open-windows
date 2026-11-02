/* SPDX-License-Identifier: MIT -- fixed awake-only prototype, reset recovery. */
#include "g289_boot_votes.h"
const G289_SPEC G289Specs[G289_VOTES]={
 {"/pm/ldob15/mV","Open289-io-v",1800},{"/pm/ldob15/en","Open289-io-e",1},
 {"/pm/smpg5/mV","Open289-wlan-v",1000},{"/pm/smpg5/en","Open289-wlan-e",1},
 {"/pm/smpg2/mV","Open289-aon-v",980},{"/pm/smpg2/en","Open289-aon-e",1},
 {"/pm/smpe4/mV","Open289-dig-v",950},{"/pm/smpe4/en","Open289-dig-e",1},
 {"/pm/smpg6/mV","Open289-rfa1-v",1900},{"/pm/smpg6/en","Open289-rfa1-e",1},
 {"/pm/smpg4/mV","Open289-rfa2-v",1350},{"/pm/smpg4/en","Open289-rfa2-e",1},
 {"/pmic/client/pcie0","Open289-pcie0",1}
};
static G200_STATUS Fail(G289_BOOT_VOTES*C,uint32_t I,G200_STATUS E){
 C->FailedIndex=I;C->FirstStatus=E;return E;
}
static G200_STATUS Cached(G289_NPA*N,const char*Name,uint32_t*V){
 G289_QUERY Q={UINT32_MAX,0,{.Raw=UINT64_MAX}};uint32_t S=UINT32_MAX;
 G200_STATUS E=N->Query(Name,0,&Q,&S);
 if(E)return E;
 if(S||Q.Type!=0)return G200_DEVICE_ERROR;
 *V=Q.Data.State;return G200_OK;
}
G200_STATUS G289BootVote(G289_BOOT_VOTES*C,G289_NPA*N,const G200_LEASE*L){
 if(!C||!N||!L)return G200_INVALID;
 if(C->Attempted||C->CreatedMask||C->IssuedMask)return G200_ABORTED;
 const uint64_t Need=G200_W_COLD_SELECTED|G200_W_PERST_ASSERTED|G200_W_NO_PCI_CONSUMER;
 if(!L->BootEpoch||!L->OwnerEpoch||L->BootServicesActive!=1||L->Exclusive!=1||
 !L->BackendIdentityPinned||L->NowUs>L->ExpiresUs||(L->Witnesses&Need)!=Need)return G200_NOT_READY;
 if(N->Version!=0x10003||!N->Create||!N->Request||!N->Available||!N->Query)return G200_UNSUPPORTED;
 C->Attempted=1;C->RetainUntilReset=1;C->BootEpoch=L->BootEpoch;C->OwnerEpoch=L->OwnerEpoch;
 C->FailedIndex=UINT32_MAX;C->Stage=1;
 /* Complete fixed availability/cached-state preflight before any creation.
  * These values are diagnostics, never claimed to be raw APSS baselines. */
 for(uint32_t I=0;I<G289_VOTES;I++){
  uint32_t S=UINT32_MAX;G200_STATUS E=N->Available(G289Specs[I].Resource,&S);
  if(E)return Fail(C,I,E);
  if(S)return Fail(C,I,G200_NOT_READY);
  E=Cached(N,G289Specs[I].Resource,&C->CachedBefore[I]);if(E)return Fail(C,I,E);
 }
 C->Stage=2;
 for(uint32_t I=0;I<G289_VOTES;I++){
  G200_STATUS E=N->Create(G289Specs[I].Resource,G289Specs[I].Client,0x40,0,0,&C->Handle[I]);
  /* Retain any nonnull handle even on anomalous EFI status. */
  if(C->Handle[I])C->CreatedMask|=1u<<I;
  if(E)return Fail(C,I,E);
  if(!C->Handle[I])return Fail(C,I,G200_DEVICE_ERROR);
  for(uint32_t J=0;J<I;J++)if(C->Handle[I]==C->Handle[J])return Fail(C,I,G200_DEVICE_ERROR);
 }
 C->Stage=3;
 for(uint32_t I=0;I<G289_VOTES;I++){
  C->IssuedMask|=1u<<I; /* Set BEFORE potentially blocking stock request. */
  G200_STATUS E=N->Request(C->Handle[I],G289Specs[I].Request);
  if(E)return Fail(C,I,E);
  C->ReturnedMask|=1u<<I;
  E=Cached(N,G289Specs[I].Resource,&C->CachedAfter[I]);if(E)return Fail(C,I,E);
  if(C->CachedAfter[I]<G289Specs[I].Request)return Fail(C,I,G200_DEVICE_ERROR);
  C->ObservedMask|=1u<<I;
 }
 C->Stage=4;return G200_OK;
}
