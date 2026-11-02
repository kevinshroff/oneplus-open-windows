/* SPDX-License-Identifier: MIT -- fixed diagnostic resources, not PnP claims. */
#ifndef G74_ADAPTER_POLICY_H
#define G74_ADAPTER_POLICY_H
#include <stdint.h>
typedef struct {uint32_t Base,Bytes,Writable;}G74_IO_RANGE;
#define G74_IO_RANGES 10u
extern const G74_IO_RANGE G74IoRanges[G74_IO_RANGES];
int G74IoReadAllowed(uint32_t);
int G74IoWriteAllowed(uint32_t,uint32_t);
#endif
