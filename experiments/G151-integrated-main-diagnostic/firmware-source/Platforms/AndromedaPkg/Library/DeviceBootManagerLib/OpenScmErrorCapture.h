/* SPDX-License-Identifier: MIT
 * Bounded capture of the original SCM's formatted 32-bit error decision.
 * No native API, MMIO, secure call, allocation or arbitrary-address selector.
 */
#ifndef OPEN_SCM_ERROR_CAPTURE_H
#define OPEN_SCM_ERROR_CAPTURE_H
typedef unsigned long long OL_U64;
typedef unsigned int OL_U32;
#define OL_MAGIC 0x31474f4c31353147ULL /* G151LOG1 */
#define OL_RECORDS 4u
#define OL_STACK_BELOW 0x4000ULL
#define OL_STACK_ABOVE 0x100ULL
#define OL_MIN_STACK_ANCHOR (0x80000000ULL+OL_STACK_BELOW)
typedef struct {
 OL_U32 Command,RawStatus,Sequence,TextBytes;
 OL_U32 ImageId,Reserved;
 OL_U64 ApiStatus,ApiResult0;
} OL_RECORD;
typedef struct {
 OL_U32 Size,Version;
 OL_U64 Magic,ImageBase,CacheSlot,SavedCache,Proxy;
 OL_U64 HookStatus,RestoreStatus,OriginalMethod,StackLow,StackHigh;
 OL_U32 HookStores,FatalRestore,SinkCalls,Ignored;
 OL_U32 Matched,Rejected,Active,PendingCommand;
 OL_U32 Count,DiagnosticStop,ParserFault,OtherCalls;
 OL_U32 OriginalCalls,Reserved;
 OL_RECORD Records[OL_RECORDS];
} OL_REPORT;
typedef struct {
 OL_REPORT Report;
 OL_U32 BeginCount,PendingSequence,PendingImage;
} OL_STATE;
enum {OL_BAD_STATE=1,OL_BAD_LENGTH=2,OL_BAD_STACK=4,OL_BAD_FORMAT=8,
      OL_WRONG_COMMAND=16,OL_CAPACITY=32,OL_DUPLICATE=64};
void OpenScmLogInit(OL_STATE *);
unsigned OpenScmLogBegin(OL_STATE *,OL_U32 command,OL_U64 image,
                        OL_U32 sequence,OL_U64 stack_anchor);
void OpenScmLogEnd(OL_STATE *,OL_U64 api_status,OL_U64 api_result0);
OL_U64 OpenScmLogConsume(OL_STATE *,const void *,OL_U64 bytes);
#endif
