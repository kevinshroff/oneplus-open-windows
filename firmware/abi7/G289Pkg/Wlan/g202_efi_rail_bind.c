/* SPDX-License-Identifier: MIT
 * Source-only exact locator for the two compiled interfaces. No EFI entrypoint
 * or initialization/rail request is run by binding. All methods lack This
 * except CmdDb's query, as established separately from actual ARM64 bodies.
 */
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include "g202_rpmh_abi.h"
G202_STATUS G202BindRailProtocols(G202_RAIL_CALLER*C){
 if(!C||C->Rpmh||C->CmdDb||C->Client||C->Resolved)return G202_ERR(2);
 EFI_GUID Rpmh={0xe1d0b573,0xf29f,0x495d,{0x93,0x52,0xca,0x0d,0xd4,0x2a,0x0a,0x74}};
 EFI_GUID CmdDb={0x1c34f691,0xd33d,0x4e14,{0xb8,0xf8,0x32,0xc6,0xc0,0x29,0xe9,0x5b}};
 G202_RPMH_PROTOCOL*R=NULL;G202_CMDDB_PROTOCOL*D=NULL;
 EFI_STATUS E=gBS->LocateProtocol(&Rpmh,NULL,(VOID**)&R);if(EFI_ERROR(E))return E;
 E=gBS->LocateProtocol(&CmdDb,NULL,(VOID**)&D);if(EFI_ERROR(E))return E;
 if(!R||!D||R->Version!=0x10001||D->Version!=0x10000)return G202_ERR(3);
 C->Rpmh=R;C->CmdDb=D;return 0;
}
