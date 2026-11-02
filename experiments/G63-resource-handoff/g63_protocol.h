/* SPDX-License-Identifier: MIT */
#ifndef G63_PROTOCOL_H
#define G63_PROTOCOL_H
#include <stdint.h>
#define G63_MAGIC UINT64_C(0x315352333647504f)
#define G63_IOCTL_QUERY UINT32_C(0x002267c0)
#define G63_CAPACITY 8u
#define G63_RECORD_BYTES 32u
#define G63_RAW_CAP 1u
#define G63_TRANSLATED_CAP 2u
#define G63_DESCRIPTOR_SIZE 4u
#define G63_RAW_MISSING 8u
#define G63_TRANSLATED_MISSING 16u
#define G63_COUNT_MISMATCH 32u

typedef struct {uint32_t Size,Version;uint64_t Magic;}G63_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,Irql,FirmwareBytes;
 uint32_t FirmwareMatch,FirmwareStatus,PrepareCalls,ReleaseCalls;
 uint32_t D0Entries,D0Exits,InD0,CaptureComplete;
 uint32_t RawCount,TranslatedCount,DescriptorBytes,Capacity;
 uint32_t StoredRaw,StoredTranslated,CaptureFlags,Reserved;
 uint8_t Raw[G63_CAPACITY][G63_RECORD_BYTES];
 uint8_t Translated[G63_CAPACITY][G63_RECORD_BYTES];
}G63_REPORT;
_Static_assert(sizeof(G63_REQUEST)==16,"G63 request ABI");
_Static_assert(sizeof(G63_REPORT)==608,"G63 report ABI");
#endif
