/* SPDX-License-Identifier: MIT */
#ifndef G715_SMMU_IDENTITY_H
#define G715_SMMU_IDENTITY_H
#include "g403_platform.h"
typedef struct {
 uint32_t Stage,Code,Writes,Prepared;
 uint32_t Id0,Id1,NumSmr,NumCb,PageSize,Pages;
 uint32_t SlotRoot,CbRoot,SlotEp,CbEp;
 uint32_t SmrRoot,S2crRoot,SmrEp,S2crEp,SctlrRoot,CbarRoot,Cba2rRoot,SctlrEp,CbarEp,Cba2rEp;
} G715_RESULT;
int G715PrepareIdentity(const G403_IO*,G715_RESULT*);
#endif
