/** @file Read-only UEFI footprint inventory. SPDX-License-Identifier: BSD-2-Clause-Patent **/
#ifndef OPEN_KERNEL_FOOTPRINT_H
#define OPEN_KERNEL_FOOTPRINT_H
#include <Uefi.h>
typedef VOID (*OPEN_KERNEL_REPORT)(CONST CHAR8 *Format, ...);
/* Fixed published-inventory policy only; not CPU permission or DMA ownership. */
BOOLEAN OpenKernelWindowInventoryComplete(VOID);
VOID OpenAppendKernelFootprint (OPEN_KERNEL_REPORT Report);
#endif
