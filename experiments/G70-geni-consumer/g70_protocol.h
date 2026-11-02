/* SPDX-License-Identifier: MIT */
#ifndef G70_PROTOCOL_H
#define G70_PROTOCOL_H
#include <stdint.h>
#define G70_MAGIC UINT64_C(0x314e45473037504f)
#define G70_IOCTL_QUERY UINT32_C(0x002267dc)
#define G70_IOCTL_CYCLE UINT32_C(0x0022e7e0)
#define G70_PAGES 3u
#define G70_REGISTERS 6u
#define G70_EVENTS 96u
#define G70_VOTE_MASK UINT32_C(0x04300000)
typedef struct { uint32_t Size,Version; uint64_t Magic,Nonce; } G70_REQUEST;
typedef struct { uint32_t Kind,Register,Value,Phase; } G70_EVENT;
typedef struct {
 uint64_t Nonce;
 uint32_t Code,RestoreError,Restored,Phase,Reads,Writes,Waits,TraceCount;
 uint32_t DirtyMask,Active;
 uint32_t Before[6],Enabled[6],After[6];
 G70_EVENT Trace[G70_EVENTS];
} G70_CLOCK_RESULT;
typedef struct {
 uint32_t Code,ReadCount,CompletePasses,IdentityMatch,Stable,Reserved;
 uint32_t First[10],Second[10];
} G70_PROBE_RESULT;
typedef struct {
 uint32_t Size,Version; uint64_t Magic;
 uint32_t KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,FirmwareStatus;
 uint32_t PrepareCalls,ReleaseCalls,D0Entries,D0Exits,InD0,Removed;
 uint32_t RawCount,TranslatedCount,ResourceOK,MappingMask,MapCalls,UnmapCalls;
 uint8_t Raw[5][20],Translated[5][20];
 uint32_t CycleAttempts,Reserved;
 G70_CLOCK_RESULT Clock;
 G70_PROBE_RESULT Probe;
} G70_REPORT;
_Static_assert(sizeof(G70_REQUEST)==24,"G70 request ABI");
_Static_assert(sizeof(G70_CLOCK_RESULT)==1656,"G70 clock ABI");
_Static_assert(sizeof(G70_PROBE_RESULT)==104,"G70 probe ABI");
_Static_assert(sizeof(G70_REPORT)==2056,"G70 report ABI");
#endif
