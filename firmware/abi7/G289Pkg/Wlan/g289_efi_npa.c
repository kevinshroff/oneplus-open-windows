/* SPDX-License-Identifier: MIT -- compile only inside pre-EBS firmware. */
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include "g289_boot_votes.h"
G200_STATUS G289BindNpa(G289_NPA**N){
 if(!N||*N)return G200_INVALID;
 EFI_GUID G={0x79d6c870,0x725e,0x489e,{0xa0,0xa1,0x27,0xe7,0xa5,0xd0,0xcb,0x35}};
 return gBS->LocateProtocol(&G,0,(VOID**)N);
}
