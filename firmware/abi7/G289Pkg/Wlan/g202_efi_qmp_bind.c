/* SPDX-License-Identifier: GPL-2.0-only — exact source physical transport.
 * No GPIO/PHY/PCIe mapping, no firmware entrypoint, no implicit open/send.
 */
#include <Uefi.h>
#include <Library/IoLib.h>
#include <Library/ArmLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "g202_qmp.h"
static int Msg(uint64_t A){return A>=0xc300000&&A<=0xc3003fc&&!(A&3U);}
static G202_STATUS Read(void*O,uint64_t A,uint32_t*V){(void)O;if(!V||!Msg(A))return G202_ERR(2);ArmDataMemoryBarrier();*V=MmioRead32((UINTN)A);ArmDataMemoryBarrier();return 0;}
static G202_STATUS Write(void*O,uint64_t A,uint32_t V){(void)O;if(!Msg(A)&&A!=0x40800c)return G202_ERR(2);if(A==0x40800c&&V)return G202_ERR(2);ArmDataMemoryBarrier();MmioWrite32((UINTN)A,V);ArmDataMemoryBarrier();return 0;}
static G202_STATUS Stall(void*O,uint32_t Us){(void)O;return Us==1000?gBS->Stall(1000):G202_ERR(2);}
G202_STATUS G202BindEfiQmp(G202_QMP*C){
 if(!C||C->Io.Read32||C->Io.Write32||C->Opened||C->Uncertain||C->Pending||C->ChannelChanged)return G202_ERR(2);
 C->Io=(G202_QMP_IO){NULL,Read,Write,Stall};return 0;
}
