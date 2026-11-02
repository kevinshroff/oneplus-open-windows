/* SPDX-License-Identifier: MIT
 * Concrete pre-ExitBootServices binding; source only, no firmware build.
 * Uses the pinned reference EFIClock.h whose prefix was checked against the
 * exact retained OnePlus ClockDxe v0x1000a. No guessed protocol slot calls.
 */
#include <Uefi.h>
#include <Protocol/EFIClock.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/ArmLib.h>
#include "g200_clock.h"
_Static_assert(sizeof(UINTN)==8,"G200 requires the audited ARM64 ABI");
_Static_assert(offsetof(EFI_CLOCK_PROTOCOL,GetClockID)==8,"Clock ABI");
_Static_assert(offsetof(EFI_CLOCK_PROTOCOL,IsClockOn)==40,"Clock ABI");
_Static_assert(offsetof(EFI_CLOCK_PROTOCOL,GetClockPowerDomainID)==80,"Clock ABI");
_Static_assert(offsetof(EFI_CLOCK_PROTOCOL,ResetClock)==128,"Clock ABI");
static uintptr_t mRateId;
static G200_STATUS GetId(void*P,const char*N,uintptr_t*V){
 G200_STATUS E=((EFI_CLOCK_PROTOCOL*)P)->GetClockID(P,N,V);
 if(E==0&&AsciiStrCmp(N,"gcc_pcie_0_phy_rchng_clk")==0)mRateId=*V;
 return E;
}
static G200_STATUS RateTuple(void*P,uintptr_t I,uint32_t W[2][10],uint32_t*V){
 if(!P||!W||!V||!mRateId||I!=mRateId)return G200_INVALID;
 static const UINTN A[10]={0x100000,0x100004,0x100010,0x100014,0x100018,
  0x16b058,0x16b05c,0x152000,0x16b054,0x152018};
 for(UINT32 N=0;N<2;N++)for(UINT32 J=0;J<10;J++){
  ArmDataMemoryBarrier();W[N][J]=MmioRead32(A[J]);ArmDataMemoryBarrier();
 }
 return G200ValidateRateTuple((const uint32_t(*)[10])W,V);
}
static G200_STATUS Enable(void*P,uintptr_t I){return ((EFI_CLOCK_PROTOCOL*)P)->EnableClock(P,I);}
static G200_STATUS Disable(void*P,uintptr_t I){return ((EFI_CLOCK_PROTOCOL*)P)->DisableClock(P,I);}
static G200_STATUS IsEnabled(void*P,uintptr_t I,uint8_t*V){return ((EFI_CLOCK_PROTOCOL*)P)->IsClockEnabled(P,I,V);}
static G200_STATUS IsOn(void*P,uintptr_t I,uint8_t*V){return ((EFI_CLOCK_PROTOCOL*)P)->IsClockOn(P,I,V);}
static G200_STATUS SetHz(void*P,uintptr_t I,uint32_t H,uint32_t M,uint32_t*V){return ((EFI_CLOCK_PROTOCOL*)P)->SetClockFreqHz(P,I,H,(EFI_CLOCK_FREQUENCY_TYPE)M,V);}
static G200_STATUS GetHz(void*P,uintptr_t I,uint32_t*V){return ((EFI_CLOCK_PROTOCOL*)P)->GetClockFreqHz(P,I,V);}
static G200_STATUS GetDomain(void*P,const char*N,uintptr_t*V){return ((EFI_CLOCK_PROTOCOL*)P)->GetClockPowerDomainID(P,N,V);}
static G200_STATUS EnableDomain(void*P,uintptr_t I){return ((EFI_CLOCK_PROTOCOL*)P)->EnableClockPowerDomain(P,I);}
static G200_STATUS DisableDomain(void*P,uintptr_t I){return ((EFI_CLOCK_PROTOCOL*)P)->DisableClockPowerDomain(P,I);}
G200_STATUS G200BindEfiClock(G200_CLOCK_API*A,const G200_LEASE*L){
 if(!A||!L||!L->BootServicesActive||!L->BackendIdentityPinned)return G200_NOT_READY;
 EFI_GUID Guid=EFI_CLOCK_PROTOCOL_GUID;EFI_CLOCK_PROTOCOL*P=NULL;
 EFI_STATUS E=gBS->LocateProtocol(&Guid,NULL,(VOID**)&P);
 if(EFI_ERROR(E))return E;
 if(!P||P->Version!=0x1000a)return G200_UNSUPPORTED;
 *A=(G200_CLOCK_API){P,P->Version,GetId,Enable,Disable,IsEnabled,IsOn,SetHz,GetHz,GetDomain,EnableDomain,DisableDomain,RateTuple};
 return G200_OK;
}
/* This file intentionally supplies no EFI entrypoint, event registration,
 * ResetClock alias, SelectExternalSource index, or PNP0A08 publication. The
 * source-defined reset/mux fallback is separate in g200_gcc_controls.c.
 * A real regulator/reference/ICC/pin owner remains an integration dependency. */
