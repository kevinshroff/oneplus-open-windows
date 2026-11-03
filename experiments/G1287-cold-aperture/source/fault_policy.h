#pragma once
#ifndef OGO_GPU_FIRST_FAULT_TUPLE
#define OGO_GPU_FIRST_FAULT_TUPLE 0
#endif
#if OGO_GPU_FIRST_FAULT_TUPLE != 0 && OGO_GPU_FIRST_FAULT_TUPLE != 1
#error OGO_GPU_FIRST_FAULT_TUPLE must be exactly 0 or 1
#endif
#if defined(_KERNEL_MODE)
#include <ntifs.h>
typedef ULONG OF_WORD;typedef LONG OF_LONG;
#define OF_ALLONES MAXULONG
#else
#include <stdint.h>
typedef uint32_t OF_WORD;typedef int32_t OF_LONG;
#define OF_ALLONES UINT32_MAX
#endif
#if OGO_GPU_FIRST_FAULT_TUPLE
#include "g1339_fault_tuple.h"
#endif
typedef struct {volatile OF_LONG Events,Fatal;OF_WORD LastStatus[3],AckWrites,InvalidReads;
#if OGO_GPU_FIRST_FAULT_TUPLE
 OF_FIRST_FAULT First;
#endif
}OF_JOURNAL;
OF_WORD OfAckPolicy(OF_JOURNAL*,OF_WORD index,OF_WORD observed);
