/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "a740_hal.h"
#include "g196_preflight.h"
/* Current-generation owner facts, not defaults or an authorization token.
 * Source profile70201 = reviewed Open gen7-2-1; producer must establish actual
 * chip/speed-bin applicability before G321 startup. DDR type is required:
 * source7 overrides HBB14, admitted non-DDR4 type8 uses core HBB16.
 * CachePolicy1 explicitly selects no owned LLCC slice; SecurePolicy1 admits
 * no protected BO/range. Hardware zero-state checks independently enforce it. */
typedef struct {ULONGLONG Generation;ULONG SourceProfile,DdrType,CachePolicy,SecurePolicy;} G456_FACTS;
typedef struct {ULONG Bank,ByteOffset,Value,Operation;NTSTATUS Status;} G456_ACCESS;
typedef struct {
 ULONG Stage,Count,Writes,Reads,HwcgSkipped,HighestBankBit,AhbValue,AhbSamples;
 NTSTATUS AhbCallStatus;
 NTSTATUS Status;BOOLEAN Attempted,Complete,Retained;
 G456_ACCESS Access[1024];
} G456_REPORT;
NTSTATUS G456ValidateFacts(const G456_FACTS *,const g196_preflight *,ULONGLONG);
struct G433_RUNTIME;
NTSTATUS G456ConfigureGpuStopped(struct G433_RUNTIME *);
