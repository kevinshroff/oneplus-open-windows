/* SPDX-License-Identifier: MIT -- fixed diagnostic resources, not PnP claims. */
#ifndef G90_ADAPTER_POLICY_H
#define G90_ADAPTER_POLICY_H
#include <stdint.h>
typedef struct {uint32_t Base,Bytes,Writable;}G90_IO_RANGE;
#define G90_IO_RANGES 10u
extern const G90_IO_RANGE G90IoRanges[G90_IO_RANGES];
int G90IoReadAllowed(uint32_t);
int G90IoWriteAllowed(uint32_t,uint32_t);
#endif
