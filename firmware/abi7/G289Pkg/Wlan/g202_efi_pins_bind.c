/* SPDX-License-Identifier: MIT — source-only binding, no EFI entrypoint. */
#include <Uefi.h>
#include <Library/IoLib.h>
#include <Library/ArmLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/EFITlmm.h>
#include "g202_pins.h"
_Static_assert(sizeof(EFI_QCOM_TLMM_PROTOCOL)==sizeof(G202_TLMM_PROTOCOL),"Full pinned TLMM header");
static G202_STATUS Read(void*O,uint64_t A,uint32_t*V){
 (void)O;if(!V)return G202_ERR(2);
 int Allowed=0;static const uint32_t P[]={80,83,94,95,96};
 for(uint32_t I=0;I<5;I++){uint64_t B=UINT64_C(0xf100000)+(uint64_t)P[I]*0x1000;
  if(A==B||A==B+4||(P[I]!=83&&A==B+8))Allowed=1;
 }
 if(!Allowed)return G202_ERR(2);
 ArmDataMemoryBarrier();*V=MmioRead32((UINTN)A);ArmDataMemoryBarrier();return 0;
}
static G202_STATUS Stall(void*O,uint32_t Us){(void)O;return Us==1000?gBS->Stall(1000):G202_ERR(2);}
G202_STATUS G202BindEfiPins(G202_PINS*C){
 if(!C||C->Tlmm||C->Prepared||C->Touched||C->Uncertain)return G202_ERR(2);
 EFI_GUID G=QCOM_TLMM_PROTOCOL_GUID;G202_TLMM_PROTOCOL*T=NULL;
 EFI_STATUS E=gBS->LocateProtocol(&G,NULL,(VOID**)&T);if(EFI_ERROR(E))return E;
 if(!T||T->Revision!=1||!T->ConfigGpio||!T->GpioOut||!T->GpioIn)return G202_ERR(3);
 C->Tlmm=T;C->Io=(G202_PIN_IO){NULL,Read,Stall};return 0;
}
