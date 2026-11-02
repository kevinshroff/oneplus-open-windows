/* SPDX-License-Identifier: MIT -- fixed diagnostic resources, not PnP claims. */
#ifndef G93_ADAPTER_POLICY_H
#define G93_ADAPTER_POLICY_H
#include <stdint.h>
typedef struct {uint32_t Base,Bytes,Writable;}G93_IO_RANGE;
#define G93_IO_RANGES 10u
extern const G93_IO_RANGE G93IoRanges[G93_IO_RANGES];
int G93IoReadAllowed(uint32_t);
int G93IoWriteAllowed(uint32_t,uint32_t);
#endif
