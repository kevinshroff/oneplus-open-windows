#ifndef OPEN_G79_READ_ONLY_BLOCK_IO_H
#define OPEN_G79_READ_ONLY_BLOCK_IO_H
#ifndef OPEN_RO_TEST
#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Library/BaseMemoryLib.h>
#endif

#define OPEN_RO_CHUNK 65536U
typedef struct {
  EFI_BLOCK_IO_PROTOCOL Io;
  EFI_BLOCK_IO_MEDIA Media;
  EFI_BLOCK_IO_PROTOCOL *Source;
  VOID *Bounce;
  UINT32 SourceMediaId;
  UINT64 ReadCalls, ReadBytes, DeniedWrites, Failures;
} OPEN_RO_VOLUME;

EFI_STATUS OpenInitReadOnlyVolume (OPEN_RO_VOLUME *Volume,
  EFI_BLOCK_IO_PROTOCOL *Source, VOID *Bounce, UINT64 ExposedBlocks);
#endif
