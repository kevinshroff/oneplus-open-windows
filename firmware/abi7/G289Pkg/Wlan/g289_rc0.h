/* SPDX-License-Identifier: GPL-2.0-only -- bounded port of pci-msm.c RC0. */
#ifndef G289_RC0_H
#define G289_RC0_H
#include "g200_clock.h"
#include "g202_pins.h"
typedef struct {
 uint32_t Attempted,Stage,WriteAttempts,PhyWords,PhyPolls,LinkPolls,ConfigPolls;
 uint32_t Uncertain,PerstReleased,IdentityValid;
 uint32_t RootId,RootClass,RootLinkCap,PhyStatus,ElbiStatus,LinkStatus;
 uint32_t EndpointId,EndpointClass,EndpointSubsystem,EndpointCommand;
 G200_STATUS FirstStatus;
}G289_RC0;
/* IO callback is the existing fixed GCC interface shape; backend must admit
 * only G289's fixed RC0 addresses after actual G200 physical admission.
 * No BAR allocation, BME, MSI, SID/DMA, ACPI publication or MHI access.
 * PRECONDITION: G200 clock context is exactly at pre-PIPE step11 and the
 * lease actually earns all G200_BEFORE_ACCESS dependencies, including ICC.
 * Diagnostic policy differs from OEM: interrupts stay masked, and Gen1 is
 * requested for first identity. This is not an enumeration-ready host bridge.
 */
G200_STATUS G289RcIdentity(G289_RC0*,G200_CLOCK_CONTEXT*,G200_LEASE*,
 G202_PINS*,const G200_GCC_IO*,const G200_GCC_IO*,const uint32_t Samples[2][24]);
#endif
