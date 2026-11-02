/** @file Read-only UEFI footprint inventory. SPDX-License-Identifier: BSD-2-Clause-Patent **/
#ifndef OPEN_KERNEL_FOOTPRINT_H
#define OPEN_KERNEL_FOOTPRINT_H
#include <Uefi.h>
typedef VOID (*OPEN_KERNEL_REPORT)(CONST CHAR8 *Format, ...);
VOID OpenAppendKernelFootprint (OPEN_KERNEL_REPORT Report);
#endif
