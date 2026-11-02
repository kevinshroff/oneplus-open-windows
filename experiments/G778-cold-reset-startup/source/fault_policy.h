#pragma once
#if defined(_KERNEL_MODE)
#include <ntifs.h>
typedef ULONG OF_WORD;typedef LONG OF_LONG;
#define OF_ALLONES MAXULONG
#else
#include <stdint.h>
typedef uint32_t OF_WORD;typedef int32_t OF_LONG;
#define OF_ALLONES UINT32_MAX
#endif
typedef struct {volatile OF_LONG Events,Fatal;OF_WORD LastStatus[2],AckWrites,InvalidReads;}OF_JOURNAL;
OF_WORD OfAckPolicy(OF_JOURNAL*,OF_WORD index,OF_WORD observed);
