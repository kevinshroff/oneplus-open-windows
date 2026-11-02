/* SPDX-License-Identifier: MIT. Internal member of the legacy touch owner. */
#ifndef G293_KEYS_H
#define G293_KEYS_H
#include <ntifs.h>
#include <wdf.h>
#include "g99_core.h"
#include "vhf291.h"
#include "protocol293.h"
#ifndef G293_POWER_REPORTS
#define G293_POWER_REPORTS 0
#endif
typedef struct {
 HANDLE Thread;KEVENT Stop;
 WDFDEVICE Device;void*Owner;int(*Available)(void*);int(*Admission)(void*);int(*Present)(void*);
 PVOID Maps[5];G99_RESULT*Scratch;ULONG GateHeld,Reads,Writes,Guard;
 ULONGLONG Frequency,Epoch,Sequence;
 G293_KEY_STREAM Core;VHF291 Vhf;P291 Observe;
 KSPIN_LOCK CacheLock;G293_STATUS Cached;G308_FAILURE FirstFailure;ULONGLONG AtUs,PowerDowns,LastDownUs;
 ULONG StablePower;volatile LONG Running;
 volatile LONG LastStatus,LastCoreCode,LastStreamCode,LastRaw,LastPower;
 volatile LONG64 Samples;
}G293_KEYS;
void G293KeysInitialize(G293_KEYS*,WDFDEVICE,void*,int(*available)(void*),int(*admission)(void*),int(*present)(void*));
/* Owner Control lock serializes Start/Stop; worker never takes Control. */
NTSTATUS G293KeysStart(G293_KEYS*);
NTSTATUS G293KeysStop(G293_KEYS*);
void G293KeysStatus(G293_KEYS*,G293_STATUS*);
void G308KeysFailure(G293_KEYS*,G308_FAILURE*);
#endif
