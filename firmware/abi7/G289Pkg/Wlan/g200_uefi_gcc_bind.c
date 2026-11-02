/* SPDX-License-Identifier: MIT
 * Concrete AON GCC I/O binding; source only, no EFI entrypoint.
 * Exact source-defined addresses are also within the old G125 GCC maps.
 * The platform must pin current firmware/resource identity and hold its lease.
 */
#include <Uefi.h>
#include <Library/IoLib.h>
#include <Library/ArmLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "g200_clock.h"
static int Allowed(uint64_t A){return A==0x16b070||A==0x16b000||A==0x16c01c;}
static G200_STATUS Read(void*O,uint64_t A,uint32_t*V){
 (void)O;if((!Allowed(A)&&A!=0x152008&&A!=0x16b048)||!V)return G200_INVALID;
 ArmDataMemoryBarrier();*V=MmioRead32((UINTN)A);ArmDataMemoryBarrier();return 0;
}
static G200_STATUS Write(void*O,uint64_t A,uint32_t V){
 (void)O;if(!Allowed(A))return G200_INVALID;
 ArmDataMemoryBarrier();MmioWrite32((UINTN)A,V);ArmDataMemoryBarrier();return 0;
}
static G200_STATUS Stall(void*O,uint32_t Us){(void)O;return Us==1000?gBS->Stall(1000):G200_INVALID;}
G200_STATUS G200BindEfiGccIo(G200_GCC_IO*I,const G200_LEASE*L){
 if(!I||!L||L->BootServicesActive!=1||L->Exclusive!=1||L->BackendIdentityPinned!=1)return G200_NOT_READY;
 *I=(G200_GCC_IO){NULL,Read,Write,Stall};return 0;
}
