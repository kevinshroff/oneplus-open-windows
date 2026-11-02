#ifndef OPEN_G80_PINNED_BLOCK_IO_H
#define OPEN_G80_PINNED_BLOCK_IO_H
#include "ReadOnlyBlockIo.h"
#include "OpenSha256.h"
#define OPEN_PIN_CHUNK 65536U
#define OPEN_PIN_COUNT 16384U
#define OPEN_PIN_BLOCKS 0x40000U
// IO is at offset0 through Ro; all unmodified callbacks remain read-only.
typedef struct {
 OPEN_RO_VOLUME Ro;
 CONST UINT8 *Hashes;
 UINT8 *Check;
 BOOLEAN Undo, Frozen;
 EFI_STATUS Fault;
 UINT64 WrittenChunks, AlreadyChunks;
} OPEN_PIN_VOLUME;
EFI_STATUS OpenInitPinnedVolume (OPEN_PIN_VOLUME *V, EFI_BLOCK_IO_PROTOCOL *Source,
 VOID *Dma, VOID *Check, CONST UINT8 *Hashes, BOOLEAN Undo);
#endif
