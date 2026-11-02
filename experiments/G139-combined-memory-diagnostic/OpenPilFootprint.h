/** @file Read-only UEFI footprint inventory. SPDX-License-Identifier: BSD-2-Clause-Patent **/
#ifndef OPEN_PIL_FOOTPRINT_H
#define OPEN_PIL_FOOTPRINT_H
#include <Uefi.h>
typedef VOID (*OPEN_PIL_REPORT)(CONST CHAR8 *Format, ...);
VOID OpenAppendPilFootprint (OPEN_PIL_REPORT Report);
#endif
