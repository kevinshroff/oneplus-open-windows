/* SPDX-License-Identifier: MIT -- selected EDK2 loader mutates ImageBase. */
#ifndef G417_LOADED_BASE_H
#define G417_LOADED_BASE_H
static inline BOOLEAN G417LoadedBaseMatches(UINT64 header,UINTN loaded)
{return header==(UINT64)loaded;}
static inline BOOLEAN G417PeOffsetValid(UINTN pe,UINTN bytes)
{return pe==CLOCK_PE_OFFSET&&pe<=0x1000u-0x108u&&bytes>=CLOCK_IMAGE_BYTES;}
#endif
