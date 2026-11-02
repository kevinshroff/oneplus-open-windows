/* SPDX-License-Identifier: MIT */
#include "g200_clock.h"
const G200_RESOURCE_SPEC G200Resources[G200_RESOURCE_COUNT]={
 {"gcc_pcie_0_gdsc",0,1},{"gcc_pcie_0_phy_gdsc",0,1},
 {"tcsr_pcie_0_clkref_en",0,0},{"gcc_pcie_0_aux_clk",19200000,0},
 {"gcc_pcie_0_cfg_ahb_clk",0,0},{"gcc_pcie_0_mstr_axi_clk",0,0},
 {"gcc_pcie_0_slv_axi_clk",0,0},{"gcc_pcie_0_slv_q2a_axi_clk",0,0},
 {"gcc_pcie_0_phy_rchng_clk",100000000,0},{"gcc_ddrss_pcie_sf_qtb_clk",0,0},
 {"gcc_aggre_noc_pcie_axi_clk",0,0},{"gcc_pcie_0_pipe_clk",0,0}
};
/* Stock FDT order after the separate first pipe entry; power domains first.
 * ref/XO, pipe mux and fixed source are provider prerequisites, not guessed
 * SelectExternalSource indices. TCSR stays at its original list position.
 */
static const uint8_t Order[G200_RESOURCE_COUNT]={G200_CORE,G200_PHY,G200_AUX,G200_CFG,
 G200_MSTR,G200_SLV,G200_TCSR,G200_SLV_Q2A,G200_RATE,G200_DDR,G200_AGGRE,G200_PIPE};
static int Error(G200_STATUS S){return (S>>63)!=0;}
static G200_STATUS Fail(G200_CLOCK_CONTEXT*C,G200_STATUS S,uint32_t Uncertain){
 if(!C->Fault)C->FirstStatus=S;
 C->Fault=1;C->UncertainMask|=Uncertain;return S;
}
static int LeaseValid(const G200_CLOCK_CONTEXT*C,const G200_LEASE*L,uint64_t Need){
 return L&&L->BootEpoch&&L->OwnerEpoch&&L->BootServicesActive==1&&L->Exclusive==1&&
 L->BackendIdentityPinned==1&&L->NowUs<=L->ExpiresUs&&L->BootEpoch==C->Lease.BootEpoch&&
 L->OwnerEpoch==C->Lease.OwnerEpoch&&L->PowerProfile==C->Lease.PowerProfile&&L->NowUs>=C->Lease.NowUs&&
 G200LeaseHas(L,Need);
}
G200_STATUS G200ClockOpen(G200_CLOCK_CONTEXT*C,const G200_CLOCK_API*A,const G200_LEASE*L){
 if(!C||!A||!L)return G200_INVALID;
 /* Caller must zero an unused context; never erase an outstanding journal. */
 if(C->Open||C->Fault)return G200_ABORTED;
 if(A->Version!=UINT64_C(0x1000a)||!A->This||!A->GetId||!A->Enable||!A->Disable||
 !A->IsEnabled||!A->IsOn||!A->SetHz||!A->GetHz||!A->GetDomainId||!A->EnableDomain||!A->DisableDomain)return G200_UNSUPPORTED;
 C->Api=*A;C->Lease=*L;
 /* Non-enabling discovery can run before radio/parent votes. GetID may
  * register a DAL client in firmware memory; it is not a power request. */
 if(!LeaseValid(C,L,G200_W_COLD_SELECTED|G200_W_NO_PCI_CONSUMER))return Fail(C,G200_NOT_READY,0);
 C->Open=1;
 for(uint32_t I=0;I<G200_RESOURCE_COUNT;I++){
  const G200_RESOURCE_SPEC*S=&G200Resources[I];G200_CLOCK_RECORD*R=&C->R[I];
  C->DiscoverIndex=I;C->DiscoverOp=1;C->DiscoverHz=UINT32_MAX;C->DiscoverEnabled=2;C->DiscoverOn=2;
  /* ID=0 and boolean=2 catch the actual dispatch's success-with-no-output path. */
  R->Id=0;G200_STATUS E=(S->Domain?A->GetDomainId:A->GetId)(A->This,S->Name,&R->Id);
  C->DiscoverStatus=E;if(Error(E))return Fail(C,E,0);
  if(!R->Id||(R->Id>>32)||((R->Id>>16)&0xffff)!=(S->Domain?2U:1U))return Fail(C,G200_DEVICE_ERROR,0);
  for(uint32_t J=0;J<I;J++)if(C->R[J].Id==R->Id)return Fail(C,G200_DEVICE_ERROR,0);
  C->DiscoverOp=2;uint8_t V=2;E=A->IsOn(A->This,R->Id,&V);
  C->DiscoverStatus=E;if(Error(E))return Fail(C,E,0);
  if(V>1)return Fail(C,G200_DEVICE_ERROR,0);
  R->PriorOn=V;C->DiscoverOn=V;
  /* GDSCs must begin physically off for this one cold-init policy. A warm or
   * borrowed domain needs another explicit owner/handoff design. */
  if(S->Domain&&V)return Fail(C,G200_NOT_READY,0);
  if(!S->Domain){
   C->DiscoverOp=3;V=2;E=A->IsEnabled(A->This,R->Id,&V);
   C->DiscoverStatus=E;if(Error(E))return Fail(C,E,0);
   if(V>1)return Fail(C,G200_DEVICE_ERROR,0);
   R->PriorEnabled=V;C->DiscoverEnabled=V;
  }
  if(S->Hz){
   C->DiscoverOp=4;uint32_t Hz=UINT32_MAX;E=A->GetHz(A->This,R->Id,&Hz);
   C->DiscoverStatus=E;C->DiscoverHz=Hz;
   /* Actual ClockDxe 0x4528 returns DAL -8 and writes zero if no active
    * source configuration exists. Admit this exact cold, unvoted state only.
    * Zero remains UNKNOWN original frequency, never a restoration value. */
   if(E==G200_EFI_ERROR(19)&&Hz==0&&R->PriorEnabled==0){
    R->OriginalHz=0;continue;
   }
   if(E==G200_EFI_ERROR(19)&&Hz==0&&R->PriorEnabled==1&&
      R->PriorOn==1&&I==G200_RATE&&A->RateTupleHz){
    uint32_t Actual=UINT32_MAX;
    C->RateStatus=A->RateTupleHz(A->This,R->Id,C->RateWords,&Actual);
    if(Error(C->RateStatus))return Fail(C,C->RateStatus,0);
    if(Actual!=S->Hz&&Actual!=19200000U)return Fail(C,G200_DEVICE_ERROR,0);
    for(uint32_t J=0;J<10;J++)C->InitialRateWords[J]=C->RateWords[0][J];
    if(Actual!=S->Hz){
     if(!LeaseValid(C,L,G200_W_COLD_SELECTED|G200_W_NO_PCI_CONSUMER|G200_W_PERST_ASSERTED))
      return Fail(C,G200_NOT_READY,0);
     R->RateHandover=1;C->HardwareRateAdmitted=2;
    }else C->HardwareRateAdmitted=1;
    Hz=Actual;E=G200_OK;R->HardwareRate=1;
   }
   if(Error(E))return Fail(C,E,0);
   if(!Hz||Hz==UINT32_MAX)return Fail(C,G200_DEVICE_ERROR,0);
   R->OriginalHz=Hz;
   /* A previously voted shared EFI clock is borrowed, never retuned. */
   if(R->PriorEnabled&&!R->RateHandover&&Hz!=S->Hz)return Fail(C,G200_NOT_READY,0);
  }
 }
 return G200_OK;
}
G200_STATUS G200ClockNext(G200_CLOCK_CONTEXT*C,const G200_LEASE*L){
 if(!C||!C->Open||C->Fault)return G200_ABORTED;
 /* PIPE has a distinct source completion point after PHY-ready. */
 if(C->Next==G200_PREPIPE_STEPS)return G200_NOT_READY;
 uint64_t Need=G200_BEFORE_POWER;
 if(C->Next>=2)Need|=G200_W_PIPE_MUX;
 if(C->Next==G200_PREPIPE_STEPS)Need|=G200_W_PHY_PROGRAMMED|G200_W_RESETS_CYCLED;
 if(!LeaseValid(C,L,Need))return Fail(C,G200_NOT_READY,0);
 if((C->Next>=2&&!C->MuxExternalKnown)||(C->Next==G200_PREPIPE_STEPS&&!C->ResetsCycled))return Fail(C,G200_NOT_READY,0);
 C->Lease=*L;
 if(C->Next>=G200_RESOURCE_COUNT)return G200_ABORTED;
 uint32_t I=Order[C->Next];const G200_RESOURCE_SPEC*S=&G200Resources[I];G200_CLOCK_RECORD*R=&C->R[I];
 G200_STATUS E;
 if(R->RateHandover){
  /* Full fresh BEFORE_POWER lease above includes exclusive cold selection,
   * PERST and no PCI consumer at the actual local retune, not just discovery.
   * Recheck inherited XO tuple and unchanged shared PLL programming first.
   */
  uint32_t Actual=UINT32_MAX;
  C->RateStatus=C->Api.RateTupleHz(C->Api.This,R->Id,C->RateWords,&Actual);
  if(Error(C->RateStatus))return Fail(C,C->RateStatus,0);
  if(Actual!=R->OriginalHz||R->Acquired||R->RateChanged)return Fail(C,G200_NOT_READY,0);
  for(uint32_t J=2;J<=4;J++)if(C->RateWords[0][J]!=C->InitialRateWords[J])return Fail(C,G200_NOT_READY,0);
 }
 if(!S->Domain&&R->PriorEnabled&&!R->RateHandover){
  uint8_t On=2;E=C->Api.IsOn(C->Api.This,R->Id,&On);
  if(Error(E))return Fail(C,E,0);
  if(On!=1)return Fail(C,G200_DEVICE_ERROR,0);
  uint8_t Enabled=2;E=C->Api.IsEnabled(C->Api.This,R->Id,&Enabled);
  if(Error(E))return Fail(C,E,0);
  if(Enabled!=1)return Fail(C,G200_DEVICE_ERROR,0);
  if(R->HardwareRate){
   uint32_t Actual=UINT32_MAX;
   C->RateStatus=C->Api.RateTupleHz(C->Api.This,R->Id,C->RateWords,&Actual);
   if(Error(C->RateStatus))return Fail(C,C->RateStatus,0);
   if(Actual!=S->Hz)return Fail(C,G200_DEVICE_ERROR,0);
  }
  C->Next++;return G200_OK;
 }
 if(S->Hz&&R->OriginalHz!=S->Hz){
  uint32_t Actual=UINT32_MAX;
  E=C->Api.SetHz(C->Api.This,R->Id,S->Hz,3,&Actual);
  /* A mutating callback may have partially acted even when it reports error. */
  if(Error(E))return Fail(C,E,1U<<I);
  R->RateChanged=1;if(R->RateHandover)C->HardwareRateAdmitted=3;
  if(Actual!=S->Hz)return Fail(C,G200_DEVICE_ERROR,1U<<I);
  Actual=UINT32_MAX;E=C->Api.GetHz(C->Api.This,R->Id,&Actual);
  if(Error(E))return Fail(C,E,1U<<I);
  if(Actual!=S->Hz)return Fail(C,G200_DEVICE_ERROR,1U<<I);
 }
 E=(S->Domain?C->Api.EnableDomain:C->Api.Enable)(C->Api.This,R->Id);
 if(Error(E))return Fail(C,E,1U<<I);
 R->Acquired=1;if(R->RateHandover)C->HardwareRateAdmitted=4;
 uint8_t On=2;E=C->Api.IsOn(C->Api.This,R->Id,&On);
 if(Error(E))return Fail(C,E,1U<<I);
 if(On!=1)return Fail(C,G200_DEVICE_ERROR,1U<<I);
 if(!S->Domain){
  uint8_t Enabled=2;E=C->Api.IsEnabled(C->Api.This,R->Id,&Enabled);
  if(Error(E))return Fail(C,E,1U<<I);
  if(Enabled!=1)return Fail(C,G200_DEVICE_ERROR,1U<<I);
 }
 if(R->RateHandover){
  uint32_t Actual=UINT32_MAX;
  C->RateStatus=C->Api.RateTupleHz(C->Api.This,R->Id,C->RateWords,&Actual);
  if(Error(C->RateStatus))return Fail(C,C->RateStatus,1U<<I);
  if(Actual!=S->Hz||!(C->RateWords[0][9]&1U))return Fail(C,G200_DEVICE_ERROR,1U<<I);
  for(uint32_t J=2;J<=4;J++)if(C->RateWords[0][J]!=C->InitialRateWords[J])return Fail(C,G200_DEVICE_ERROR,1U<<I);
  if((C->RateWords[0][7]&C->InitialRateWords[7])!=C->InitialRateWords[7]||
     (C->RateWords[0][9]&C->InitialRateWords[9])!=C->InitialRateWords[9])return Fail(C,G200_DEVICE_ERROR,1U<<I);
  C->HardwareRateAdmitted=5;
 }
 C->Next++;return G200_OK;
}
/* G396: source BRANCH_HALT_SKIP PIPE enable precedes PHY-ready. A request
 * receipt never increments Next; physical completion after PHY-ready must do so.
 */
static G200_STATUS PipeFail(G200_CLOCK_CONTEXT*C,G200_STATUS E){
 C->Pipe.LastStatus=E;return Fail(C,E,1U<<G200_PIPE);
}
static G200_STATUS PipeProof(G200_CLOCK_CONTEXT*C,const G200_GCC_IO*I,uint8_t Physical){
 G200_PIPE_TRACE*T=&C->Pipe;uint32_t W[2][3];
 static const uint64_t A[3]={0x16b070,0x152008,0x16b048};
 for(uint32_t N=0;N<2;N++)for(uint32_t J=0;J<3;J++){
  G200_STATUS E=I->Read32(I->Opaque,A[J],&W[N][J]);if(Error(E))return PipeFail(C,E);
 }
 T->Mux=W[1][0];T->Vote=W[1][1];T->Cbcr=W[1][2];T->RawStable=1;
 for(uint32_t J=0;J<3;J++)if(W[0][J]!=W[1][J])T->RawStable=0;
 if(W[0][0]!=W[1][0]||W[0][1]!=W[1][1]||(T->Mux&3U)||!(T->Vote&(1U<<4)))return PipeFail(C,G200_DEVICE_ERROR);
 uint8_t V=2;T->OnStatus=C->Api.IsOn(C->Api.This,C->R[G200_PIPE].Id,&V);T->On=V;
 if(Error(T->OnStatus))return PipeFail(C,T->OnStatus);
 if(V>1)return PipeFail(C,G200_DEVICE_ERROR);
 V=2;T->EnabledStatus=C->Api.IsEnabled(C->Api.This,C->R[G200_PIPE].Id,&V);T->Enabled=V;
 if(Error(T->EnabledStatus))return PipeFail(C,T->EnabledStatus);
 if(V!=1)return PipeFail(C,G200_DEVICE_ERROR);
 if(Physical&&(!T->RawStable||T->On!=1||(T->Cbcr&0x80000000U)))return G200_NOT_READY;
 return G200_OK;
}
G200_STATUS G200PipeStart(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const G200_GCC_IO*I){
 if(!C||!I||!I->Read32||!C->Open||C->Fault||C->UncertainMask||
    C->Next!=G200_PREPIPE_STEPS||C->Pipe.Attempted||!C->MuxExternalKnown||!C->ResetsCycled)
  return G200_NOT_READY;
 if(!LeaseValid(C,L,G200_BEFORE_ACCESS|G200_W_PHY_PROGRAMMED))return PipeFail(C,G200_NOT_READY);
 G200_PIPE_TRACE*T=&C->Pipe;T->Attempted=1;T->Phase=1;
 T->EnableStatus=T->OnStatus=T->EnabledStatus=UINT64_MAX;
 C->UncertainMask|=1U<<G200_PIPE; /* mutating call may partially act */
 T->EnableStatus=C->Api.Enable(C->Api.This,C->R[G200_PIPE].Id);
 if(Error(T->EnableStatus))return PipeFail(C,T->EnableStatus);
 C->R[G200_PIPE].Acquired=1;T->Phase=2;
 G200_STATUS E=PipeProof(C,I,0);if(Error(E))return E;
 T->IssueOn=T->On;T->IssueEnabled=T->Enabled;T->Phase=3;T->LastStatus=G200_OK;
 C->Lease=*L;return G200_OK; /* request only; Next still11 */
}
G200_STATUS G200PipePoll(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const G200_GCC_IO*I,
 uint32_t PhyStatus,uint8_t Last){
 if(!C||!I||!I->Read32||!C->Open||C->Fault||C->Next!=G200_PREPIPE_STEPS||
    C->Pipe.Phase<3||C->Pipe.Phase>=5||C->UncertainMask!=(1U<<G200_PIPE))return G200_NOT_READY;
 if(!LeaseValid(C,L,G200_BEFORE_ACCESS|G200_W_PHY_PROGRAMMED))return PipeFail(C,G200_NOT_READY);
 C->Pipe.Phase=4;C->Pipe.Polls++;C->Pipe.PhyStatus=PhyStatus;
 G200_STATUS E=PipeProof(C,I,1);if(Error(E)&&E!=G200_NOT_READY)return E;
 if(E==G200_NOT_READY||(PhyStatus&(1U<<6))){
  C->Pipe.LastStatus=G200_NOT_READY;
  return Last?PipeFail(C,G200_NOT_READY):G200_NOT_READY;
 }
 C->Pipe.Phase=5;C->Pipe.LastStatus=G200_OK;C->UncertainMask&=~(1U<<G200_PIPE);
 C->Next++;C->Lease=*L;return G200_OK;
}
G200_STATUS G200ClockRetire(G200_CLOCK_CONTEXT*C,const G200_LEASE*L){
 if(!C||!C->Open)return G200_ABORTED;
 if(C->R[G200_RATE].RateHandover)return G200_NOT_READY; /* retained owner, no unwind */
 uint64_t Need=G200_W_PERST_ASSERTED|G200_W_NO_MAPPINGS|G200_W_NO_PCI_CONSUMER;
 if(!LeaseValid(C,L,Need)||C->UncertainMask||C->MuxExternalKnown)return G200_NOT_READY;
 /* Explicitly admitted quiescent retirement, never automatic error unwind. */
 for(uint32_t I=0;I<G200_RESOURCE_COUNT;I++)
  if(C->R[I].RateChanged&&!C->R[I].OriginalHz)return G200_NOT_READY;
 for(uint32_t N=G200_RESOURCE_COUNT;N>0;N--){
  uint32_t I=Order[N-1];G200_CLOCK_RECORD*R=&C->R[I];const G200_RESOURCE_SPEC*S=&G200Resources[I];
  if(R->RateChanged){
   uint32_t Actual=UINT32_MAX;G200_STATUS E=C->Api.SetHz(C->Api.This,R->Id,R->OriginalHz,3,&Actual);
   if(Error(E))return Fail(C,E,1U<<I);
   if(Actual!=R->OriginalHz)return Fail(C,G200_DEVICE_ERROR,1U<<I);
   R->RateChanged=0;
  }
  if(R->Acquired){
   G200_STATUS E=(S->Domain?C->Api.DisableDomain:C->Api.Disable)(C->Api.This,R->Id);
   if(Error(E))return Fail(C,E,1U<<I);
   R->Acquired=0;
  }
 }
 C->Open=0;return G200_OK;
}
static G200_STATUS PassiveReady(const uint32_t S[2][24],uint8_t Released){
 if(!S)return G200_INVALID;
 for(uint32_t I=0;I<24;I++)if(S[0][I]!=S[1][I])return G200_NOT_READY;
 /* GPIO83 is the source's one-shot PRE-POWER device selector, sampled by
  * Initial/PinPrepare before votes. Its powered input is not a readiness bit.
  * Keep stable snapshots and GPIO input/mux/EGPIO suitability; the retained
  * COLD_SELECTED lease binds the branch and RC later requires actual1107ID.
  */
 if(S[0][16]&0x123cU)return G200_NOT_READY;
 /* Both physical completion sources must agree, not just collapse votes. */
 if((S[0][0]&9U)||!(S[0][4]&0x80000000U)||!(S[0][13]&0x80000000U)||
 (S[0][5]&0x18000U)!=0x10000U||(S[0][14]&0x18000U)!=0x10000U)return G200_NOT_READY;
 if((S[0][3]&1U)||(S[0][15]&1U))return G200_NOT_READY;
 /* Existing sample must contain retained AGGRE bit12 and DDRSS bit19 votes. */
 if((S[0][2]&0x2fU)!=0x2fU||(S[0][1]&0x81000U)!=0x81000U||
    !(S[0][1]&(1U<<22)))return G200_NOT_READY;
 /* CFG/AUX/SLV/Q2A are source BRANCH_HALT_VOTED. MSTR and PIPE have
  * BRANCH_HALT_SKIP; their bit31 is not invented as an enforced source poll. */
 const uint8_t Voted[]={6,7,9,10,12};
 for(uint32_t I=0;I<sizeof(Voted);I++)if(S[0][Voted[I]]&0x80000000U)return G200_NOT_READY;
 /* PERST94 is held low as an actual GPIO output; WLAN_EN80 high output.
  * mux bits5:2 zero; OE bit9 set; egpio bit12 clear. */
 if((S[0][18]&0x123cU)!=0x200U||(S[0][19]&3U)!=(Released?3U:0U)||
 (S[0][22]&0x123cU)!=0x200U||(S[0][23]&3U)!=3U)return G200_NOT_READY;
 return G200_OK;
}
static G200_STATUS AccessReady(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const uint32_t S[2][24],uint8_t Pipe,uint8_t Released){
 if(!C||!C->Open||C->Fault||C->UncertainMask||!C->MuxExternalKnown||!C->ResetsCycled||C->Next<G200_PREPIPE_STEPS)return G200_ABORTED;
 uint64_t Need=G200_BEFORE_ACCESS;
 if(Released)Need=(Need&~G200_W_PERST_ASSERTED)|G200_W_PERST_RELEASED;
 if(Pipe)Need|=G200_W_PHY_PROGRAMMED;
 if(!LeaseValid(C,L,Need)||(Pipe&&C->Next!=G200_RESOURCE_COUNT))return G200_NOT_READY;
 if(C->R[G200_RATE].HardwareRate){
  uint32_t Actual=UINT32_MAX;
  C->RateStatus=C->Api.RateTupleHz(C->Api.This,C->R[G200_RATE].Id,C->RateWords,&Actual);
  if(Error(C->RateStatus))return Fail(C,C->RateStatus,0);
  if(Actual!=G200Resources[G200_RATE].Hz)return Fail(C,G200_DEVICE_ERROR,0);
  if(C->R[G200_RATE].RateHandover){
   if(!(C->RateWords[0][9]&1U))return Fail(C,G200_DEVICE_ERROR,0);
   for(uint32_t J=2;J<=4;J++)if(C->RateWords[0][J]!=C->InitialRateWords[J])return Fail(C,G200_DEVICE_ERROR,0);
  }
 }
 G200_STATUS E=PassiveReady(S,Released);
 if(E!=G200_OK)return E;
 if(Pipe&&(S[0][2]&(1U<<4))==0)return G200_NOT_READY;
 C->Lease=*L;return G200_OK;
}

G200_STATUS G200PassiveReady(const uint32_t S[2][24]){return PassiveReady(S,0);}
G200_STATUS G200AccessReady(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const uint32_t S[2][24],uint8_t Pipe){return AccessReady(C,L,S,Pipe,0);}
G200_STATUS G200ActiveReady(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const uint32_t S[2][24]){return AccessReady(C,L,S,1,1);}
