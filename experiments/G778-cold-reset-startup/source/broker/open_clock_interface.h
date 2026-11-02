#ifndef OPEN_CLOCK_INTERFACE_H
#define OPEN_CLOCK_INTERFACE_H
#include <ntddk.h>
#include "open_smmu_handoff.h"
static const GUID OpenClockQueryGuid={0x55210d01,0xe218,0x4af0,{0x96,0x16,0x4b,0x24,0x81,0x52,0x00,0x19}};
static const GUID OpenClockDeviceGuid={0x55220d01,0xe218,0x4af0,{0x96,0x16,0x4b,0x24,0x81,0x52,0x00,0x19}};
#define OPEN_CLOCK_VERSION 3
#define OPEN_CLOCK_GPU_CLIENT 1
#define OPEN_CLOCK_SMMU_CLIENT 2
/* Trusted source consumer callbacks verify its real START/D0 scope and drain.
 * They run under broker mutex: no reentry, blocking, lock acquisition or MMIO.
 * Call Acquire/Release within the client's already-held owner scope; current()
 * must compare actual PDO/generation/thread, not accept a caller boolean.
 * The consumer MUST pin Context and callback code until successful token
 * release, or full reset if uncertain. PDO references do NOT pin arbitrary
 * consumer context/code. No unload/free is allowed while a token is live. */
typedef NTSTATUS (*OPEN_CLOCK_CLIENT_PROOF)(PVOID,PDEVICE_OBJECT,ULONGLONG);
typedef struct {
 ULONG Size,Version,Role,Reserved;PDEVICE_OBJECT Pdo;PVOID Context;ULONGLONG Generation;
 OPEN_CLOCK_CLIENT_PROOF Current,Drained;
} OPEN_CLOCK_CLIENT;
typedef struct {ULONG Size,Version,Branches[4],Cx,Hw,Root,Cfg,DelayRequestMask,Bit0ConfirmedMask;ULONGLONG Generation,At100ns;}OPEN_CLOCK_SNAPSHOT;
typedef struct {
 INTERFACE Interface;PDEVICE_OBJECT ProviderPdo;
 NTSTATUS (*Acquire)(PVOID,const OPEN_CLOCK_CLIENT*,ULONGLONG*);
 NTSTATUS (*Release)(PVOID,ULONGLONG);
 NTSTATUS (*Snapshot)(PVOID,OPEN_CLOCK_SNAPSHOT*);
 NTSTATUS (*InspectGlobals)(PVOID,OSH_SNAPSHOT*,OSH_SNAPSHOT*,OSH_REPORT*);
}OPEN_CLOCK_INTERFACE;
#endif
