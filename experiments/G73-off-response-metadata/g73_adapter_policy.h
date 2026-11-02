/* SPDX-License-Identifier: MIT -- fixed diagnostic resources, not PnP claims. */
#ifndef G73_ADAPTER_POLICY_H
#define G73_ADAPTER_POLICY_H
#include <stdint.h>
typedef struct {uint32_t Base,Bytes,Writable;}G73_IO_RANGE;
#define G73_IO_RANGES 10u
extern const G73_IO_RANGE G73IoRanges[G73_IO_RANGES];
int G73IoReadAllowed(uint32_t);
int G73IoWriteAllowed(uint32_t,uint32_t);
#endif
