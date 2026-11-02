/* SPDX-License-Identifier: GPL-2.0-only
 * Compile-only ABI/DDI probe. No DriverEntry, driver installation or target
 * access. These functions must not be called on unqualified MMIO addresses.
 */
#include <ntddk.h>
#include <wdf.h>
#include "geni_fifo.h"
C_ASSERT(sizeof(void*)==8);
C_ASSERT(sizeof(ULONG)==4);
ULONG G27ContractRead(PULONG p) { return READ_REGISTER_ULONG(p); }
VOID G27ContractWrite(PULONG p,ULONG v) {
    WRITE_REGISTER_ULONG(p,v);
    KeMemoryBarrier();
}
WDFDEVICE G27ContractWdf(WDFDEVICE device) { return device; }
