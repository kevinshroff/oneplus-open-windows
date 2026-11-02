/* SPDX-License-Identifier: MIT -- fixed diagnostic resources, not PnP claims. */
#ifndef G89_ADAPTER_POLICY_H
#define G89_ADAPTER_POLICY_H
#include <stdint.h>
typedef struct {uint32_t Base,Bytes,Writable;}G89_IO_RANGE;
#define G89_IO_RANGES 10u
extern const G89_IO_RANGE G89IoRanges[G89_IO_RANGES];
int G89IoReadAllowed(uint32_t);
int G89IoWriteAllowed(uint32_t,uint32_t);
#endif
