/* SPDX-License-Identifier: MIT -- fixed diagnostic resources, not PnP claims. */
#ifndef G91_ADAPTER_POLICY_H
#define G91_ADAPTER_POLICY_H
#include <stdint.h>
typedef struct {uint32_t Base,Bytes,Writable;}G91_IO_RANGE;
#define G91_IO_RANGES 10u
extern const G91_IO_RANGE G91IoRanges[G91_IO_RANGES];
int G91IoReadAllowed(uint32_t);
int G91IoWriteAllowed(uint32_t,uint32_t);
#endif
