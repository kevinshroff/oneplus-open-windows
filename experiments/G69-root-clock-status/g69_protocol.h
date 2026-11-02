/* SPDX-License-Identifier: MIT */
#ifndef G69_PROTOCOL_H
#define G69_PROTOCOL_H
#include <stdint.h>
#define G69_MAGIC UINT64_C(0x314b4c433936504f)
#define G69_IOCTL_QUERY UINT32_C(0x002267d4)
#define G69_IOCTL_CYCLE UINT32_C(0x0022e7d8)
#define G69_PAGES 3u
#define G69_REGISTERS 6u
#define G69_EVENTS 96u
#define G69_VOTE_MASK UINT32_C(0x04300000)
typedef struct { uint32_t Size,Version; uint64_t Magic,Nonce; } G69_REQUEST;
typedef struct { uint32_t Kind,Register,Value,Phase; } G69_EVENT;
typedef struct {
 uint64_t Nonce;
 uint32_t Code,RestoreError,Restored,Phase,Reads,Writes,Waits,TraceCount;
 uint32_t DirtyMask,Active;
 uint32_t Before[6],Enabled[6],After[6];
 G69_EVENT Trace[G69_EVENTS];
} G69_CLOCK_RESULT;
typedef struct {
 uint32_t Size,Version; uint64_t Magic;
 uint32_t KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,FirmwareStatus;
 uint32_t PrepareCalls,ReleaseCalls,D0Entries,D0Exits,InD0,Removed;
 uint32_t RawCount,TranslatedCount,ResourceOK,MappingMask,MapCalls,UnmapCalls;
 uint8_t Raw[3][20],Translated[3][20];
 uint32_t CycleAttempts,Reserved;
 G69_CLOCK_RESULT Clock;
} G69_REPORT;
_Static_assert(sizeof(G69_REQUEST)==24,"G69 request ABI");
_Static_assert(sizeof(G69_CLOCK_RESULT)==1656,"G69 clock ABI");
_Static_assert(sizeof(G69_REPORT)==1872,"G69 report ABI");
#endif
