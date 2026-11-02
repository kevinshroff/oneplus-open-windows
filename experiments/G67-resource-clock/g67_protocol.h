/* SPDX-License-Identifier: MIT */
#ifndef G67_PROTOCOL_H
#define G67_PROTOCOL_H
#include <stdint.h>
#define G67_MAGIC UINT64_C(0x314b4c433736504f)
#define G67_IOCTL_QUERY UINT32_C(0x002267c4)
#define G67_IOCTL_CYCLE UINT32_C(0x0022e7c8)
#define G67_PAGES 3u
#define G67_REGISTERS 6u
#define G67_EVENTS 96u
#define G67_VOTE_MASK UINT32_C(0x04300000)
typedef struct { uint32_t Size,Version; uint64_t Magic,Nonce; } G67_REQUEST;
typedef struct { uint32_t Kind,Register,Value,Phase; } G67_EVENT;
typedef struct {
 uint64_t Nonce;
 uint32_t Code,RestoreError,Restored,Phase,Reads,Writes,Waits,TraceCount;
 uint32_t DirtyMask,Active;
 uint32_t Before[6],Enabled[6],After[6];
 G67_EVENT Trace[G67_EVENTS];
} G67_CLOCK_RESULT;
typedef struct {
 uint32_t Size,Version; uint64_t Magic;
 uint32_t KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,FirmwareStatus;
 uint32_t PrepareCalls,ReleaseCalls,D0Entries,D0Exits,InD0,Removed;
 uint32_t RawCount,TranslatedCount,ResourceOK,MappingMask,MapCalls,UnmapCalls;
 uint8_t Raw[3][20],Translated[3][20];
 uint32_t CycleAttempts,Reserved;
 G67_CLOCK_RESULT Clock;
} G67_REPORT;
_Static_assert(sizeof(G67_REQUEST)==24,"G67 request ABI");
_Static_assert(sizeof(G67_CLOCK_RESULT)==1656,"G67 clock ABI");
_Static_assert(sizeof(G67_REPORT)==1872,"G67 report ABI");
#endif
