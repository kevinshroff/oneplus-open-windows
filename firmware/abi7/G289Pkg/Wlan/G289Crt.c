/* SPDX-License-Identifier: MIT -- compiler-generated aggregate copy support. */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
void *memcpy(void *Destination,const void *Source,UINTN Length){return CopyMem(Destination,Source,Length);}
void *memset(void *Destination,int Value,UINTN Length){return SetMem(Destination,Length,(UINT8)Value);}
