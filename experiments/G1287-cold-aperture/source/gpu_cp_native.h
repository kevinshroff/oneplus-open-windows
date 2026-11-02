#pragma once
#include "g433_runtime.h"
#include "../reference/inactive/source/open_smmu_inactive.h"
typedef struct G982_CP {
 G433_RUNTIME Run;OSMI_TABLES Tables;PUCHAR SqeInput;PVOID Smmu;
 ULONG Phase,GxBefore,GxAfter,SqeBefore,SqeAfter,Reads,Writes,LastOffset,LastValue,LastWrite,LastValid;
 ULONG SmmuReads,SmmuWrites,SmmuPolls;NTSTATUS Status;BOOLEAN Scope,InitialOff,FirstUseConsumed,Published,Retain;
 OSH_SNAPSHOT Before,Expected,After;
}G982_CP;
struct OGO_CONTEXT_UNUSED;
