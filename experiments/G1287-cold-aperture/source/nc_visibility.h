#pragma once
#include "open_smmu_activate_wdm.h"
/* Actual allocator-ledger verification + NC device-visibility ordering.
 * No cache query fiction or caller PFN list; no MMIO or root publication. */
NTSTATUS OasMakeNcVisible(OSMA_TABLE_BINDING*);
