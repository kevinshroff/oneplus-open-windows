/* SPDX-License-Identifier: MIT */
#ifndef G735_SMMU_IDENTITY_H
#define G735_SMMU_IDENTITY_H
#include "g403_platform.h"
#define G735_BASE UINT64_C(0x15000000)
#define G735_APERTURE 0x100000u
#define G735_MAX_SMR 128u
#define G735_MAX_CB 256u
/* Diagnostic, retained until reset. Prepared means register readback only;
 * it does not certify DMA, security attribution or Windows ownership. */
typedef struct {
 uint64_t CbAddress,SmrAddress,S2crAddress,CbarAddress,Cba2rAddress;
 uint32_t Sid,Slot,Cb,Smr,S2cr,Sctlr,Cbar,Cba2r;
} G735_STREAM;
typedef struct {
 uint32_t Magic,Version,Bytes,Stage,Code,Prepared,Writes,AttemptedWrites;
 uint32_t Id0,Id1,Cr0,NumSmr,NumCb,PageSize,Pages,Span,MapCode,GateCode;
 uint64_t CbBase,LastAddress,MapStatus,SidTableAddress;
 uint32_t ParfCfg,SidEntry,SidHash;
 uint32_t LastExpected,LastReadback,LastReadbackValid,RetainUntilReset;
 uint32_t InventoryCount,PreflightVerified,GfsrBefore,Gfsynr0Before,Gfsynr1Before,GfsrAfter;
 uint32_t BeforeSmr[G735_MAX_SMR],BeforeS2cr[G735_MAX_SMR];
 G735_STREAM Stream[2];
} G735_RESULT;
int G735VerifyPreparedSid(const G403_IO*,const G403_RESULT*,G735_RESULT*);
void G735Init(G735_RESULT*);
int G735Geometry(uint32_t,uint32_t,G735_RESULT*);
int G735PrepareIdentity(const G403_IO*,G735_RESULT*);
#endif
