/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "g482_resources.h"
/* Deliberately supplied reviewed source intent, not hardware identity proof.
 * The real existing owner must independently qualify physical chip/speed-bin,
 * source GMU220MHz/hub200MHz clocks and boot interconnect/rail leases. */
typedef struct {ULONGLONG Generation;ULONG SourceProfile;const UCHAR *RscCode;SIZE_T RscBytes;} G482_BOARD_INPUT;
typedef struct {ULONG Bank,Offset,Value,Operation;NTSTATUS Status;} G482_BOARD_ACCESS;
typedef struct {ULONG Stage,Count;NTSTATUS Status;BOOLEAN Attempted,CoreConfigured,FirmwareConfigured,Retained;G482_BOARD_ACCESS Access[192];} G482_BOARD_REPORT;
struct G321_RUNTIME;
NTSTATUS G482AdmitBoard(struct G321_RUNTIME *,const G482_BOARD_INPUT *);
NTSTATUS G482ColdPreflight(struct G321_RUNTIME *);
NTSTATUS G482ConfigureCore(struct G321_RUNTIME *);
NTSTATUS G482ConfigureFirmwareReady(struct G321_RUNTIME *);
