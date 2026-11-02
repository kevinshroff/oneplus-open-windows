/* SPDX-License-Identifier: MIT
 * Exact retained gcc-kalama mux/reset controls only. No PARF/PHY/DBI/ECAM.
 * A qualified pre-OS I/O binding must preserve the exclusive lease throughout
 * these operations. A source-only callback interface is not native admission.
 */
#include "g200_clock.h"
#define MUX UINT64_C(0x16b070)
#define CORE_RESET UINT64_C(0x16b000)
#define PHY_RESET UINT64_C(0x16c01c)
static G200_STATUS Fault(G200_CLOCK_CONTEXT*C,G200_STATUS E){
 if(!C->Fault)C->FirstStatus=E;C->Fault=1;C->UncertainMask|=0x80000000U;return E;
}
static int Lease(const G200_CLOCK_CONTEXT*C,const G200_LEASE*L,uint64_t Need){
 return C&&L&&C->Open&&!C->Fault&&!C->UncertainMask&&L->BootServicesActive==1&&
 L->Exclusive==1&&L->BackendIdentityPinned==1&&L->BootEpoch==C->Lease.BootEpoch&&
 L->OwnerEpoch==C->Lease.OwnerEpoch&&L->PowerProfile==C->Lease.PowerProfile&&L->NowUs>=C->Lease.NowUs&&L->NowUs<=L->ExpiresUs&&
 G200LeaseHas(L,Need);
}
static int Io(const G200_GCC_IO*I){return I&&I->Read32&&I->Write32&&I->StallUs;}
static G200_STATUS Rmw(G200_CLOCK_CONTEXT*C,const G200_GCC_IO*I,uint64_t A,uint32_t Mask,uint32_t Value){
 uint32_t Old=0,Read=0;G200_STATUS E=I->Read32(I->Opaque,A,&Old);
 if(E)return Fault(C,E);
 E=I->Write32(I->Opaque,A,(Old&~Mask)|(Value&Mask));if(E)return Fault(C,E);
 E=I->Read32(I->Opaque,A,&Read);if(E)return Fault(C,E);
 if((Read&Mask)!=(Value&Mask))return Fault(C,G200_DEVICE_ERROR);
 return G200_OK;
}
G200_STATUS G200GccMuxExternal(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const G200_GCC_IO*I){
 if(!Io(I)||!Lease(C,L,G200_BEFORE_POWER)||C->Next!=2||C->MuxTouched)return G200_NOT_READY;
 uint32_t Old=0;G200_STATUS E=I->Read32(I->Opaque,MUX,&Old);if(E)return Fault(C,E);
 /* Deliberately narrow cold policy: preflight must have found XO selector2.
  * A different inherited mux requires a separately reviewed handoff policy. */
 if((Old&3U)!=2U)return G200_NOT_READY;
 E=Rmw(C,I,MUX,3,0);if(E)return E;
 C->MuxTouched=1;C->MuxExternalKnown=1;C->Lease=*L;return 0;
}
G200_STATUS G200GccResetPair(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const G200_GCC_IO*I){
 if(!Io(I)||!Lease(C,L,G200_BEFORE_POWER|G200_W_PIPE_MUX)||C->Next!=G200_PREPIPE_STEPS||!C->MuxExternalKnown||C->ResetsCycled)return G200_NOT_READY;
 const uint64_t Regs[2]={CORE_RESET,PHY_RESET};
 for(uint32_t N=0;N<2;N++){
  G200_STATUS E=Rmw(C,I,Regs[N],1,1);if(E)return E;
  E=I->StallUs(I->Opaque,1000);if(E)return Fault(C,E);
  E=Rmw(C,I,Regs[N],1,0);if(E)return E;
 }
 C->ResetsCycled=1;C->Lease=*L;return 0;
}
G200_STATUS G200GccMuxXo(G200_CLOCK_CONTEXT*C,const G200_LEASE*L,const G200_GCC_IO*I){
 uint64_t Need=G200_W_PERST_ASSERTED|G200_W_NO_MAPPINGS|G200_W_NO_PCI_CONSUMER;
 if(!Io(I)||!Lease(C,L,Need)||!C->MuxTouched||!C->MuxExternalKnown)return G200_NOT_READY;
 G200_STATUS E=Rmw(C,I,MUX,3,2);if(E)return E;
 C->MuxExternalKnown=0;C->Lease=*L;return 0;
}
