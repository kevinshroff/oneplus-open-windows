/** SPDX-License-Identifier: BSD-2-Clause-Patent **/
#ifndef OPEN_GPT_TYPE_MIGRATION_H
#define OPEN_GPT_TYPE_MIGRATION_H
#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/PartitionInfo.h>
#define OPEN_GPT_TYPE_RECORD_OFFSET  512
#pragma pack(1)
typedef struct {
  CHAR8 Magic[8];
  UINT32 Mode;                    // 13 apply, 14 undo
  UINT32 State;                   // 1 refused, 2 already desired, 3 complete, 4 failed
  UINT64 Status;
  UINT32 WritesAttempted;
  UINT32 WritesVerified;
  UINT32 InitialPattern[5];       // 1 original, 2 corrected, 0 unknown
  UINT64 WriteStatus[4];
  UINT64 FlushStatus[4];
  UINT64 ReadbackStatus[4];
  UINT64 WriteLba[4];
} OPEN_GPT_TYPE_RESULT;
#pragma pack()
typedef VOID (*OPEN_GPT_TYPE_LOG)(IN CONST CHAR8 *Format, ...);
VOID OpenRunG80GptTypeMigration (IN EFI_BLOCK_IO_PROTOCOL *Io,
  IN EFI_PARTITION_INFO_PROTOCOL *Info, IN UINT32 Mode,
  IN OPEN_GPT_TYPE_LOG WriteLog, OUT OPEN_GPT_TYPE_RESULT *Result);
BOOLEAN OpenG80GptTypeAllowsBoot (VOID);
EFI_STATUS OpenG80MakeCorrected (OUT UINT8 After[5][4096]);
#endif
