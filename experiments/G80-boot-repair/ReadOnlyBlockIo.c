// G79 storage facade. No callback forwards writes, resets, or flushes.
#include "ReadOnlyBlockIo.h"

STATIC EFI_STATUS EFIAPI
ReadOnlyReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN ExtendedVerification)
{
  (VOID)This; (VOID)ExtendedVerification;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
ReadOnlyWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Size, VOID *Buffer)
{
  OPEN_RO_VOLUME *V = (OPEN_RO_VOLUME *)This;
  (VOID)MediaId; (VOID)Lba; (VOID)Size; (VOID)Buffer;
  V->DeniedWrites++;
  return EFI_WRITE_PROTECTED;
}

STATIC EFI_STATUS EFIAPI
ReadOnlyFlush (EFI_BLOCK_IO_PROTOCOL *This)
{
  (VOID)This;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
ReadOnlyRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Size, VOID *Buffer)
{
  OPEN_RO_VOLUME *V = (OPEN_RO_VOLUME *)This;
  EFI_BLOCK_IO_MEDIA *M = V->Source->Media;
  EFI_STATUS Status;
  UINTN Chunk, Remaining = Size;
  UINT8 *Out = Buffer;
  UINT64 Blocks;
  if (!M->MediaPresent) { return EFI_NO_MEDIA; }
  if ((MediaId != V->Media.MediaId) || (M->MediaId != V->SourceMediaId) ||
      (M->BlockSize != 4096)) { return EFI_MEDIA_CHANGED; }
  if (Size == 0) { return EFI_SUCCESS; }
  if (Buffer == NULL) { return EFI_INVALID_PARAMETER; }
  if (Size % 4096 != 0) { return EFI_BAD_BUFFER_SIZE; }
  Blocks = Size / 4096;
  if ((Lba > V->Media.LastBlock) ||
      (Blocks - 1 > V->Media.LastBlock - Lba) ||
      (Lba > M->LastBlock) || (Blocks - 1 > M->LastBlock - Lba)) {
    return EFI_INVALID_PARAMETER;
  }
  V->ReadCalls++;
  while (Remaining != 0) {
    Chunk = Remaining > 4096 ? 4096 : Remaining;
    Status = V->Source->ReadBlocks (V->Source, V->SourceMediaId, Lba, Chunk, V->Bounce);
    if (EFI_ERROR (Status)) { V->Failures++; return Status; }
    CopyMem (Out, V->Bounce, Chunk);
    V->ReadBytes += Chunk;
    Out += Chunk; Remaining -= Chunk; Lba += Chunk / 4096;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
OpenInitReadOnlyVolume (OPEN_RO_VOLUME *V, EFI_BLOCK_IO_PROTOCOL *Source,
  VOID *Bounce, UINT64 ExposedBlocks)
{
  EFI_BLOCK_IO_MEDIA *M;
  UINTN Align;
  if ((V == NULL) || (Source == NULL) || (Source->Media == NULL) ||
      (Source->ReadBlocks == NULL) || (Bounce == NULL) || (ExposedBlocks == 0)) {
    return EFI_INVALID_PARAMETER;
  }
  M = Source->Media;
  Align = M->IoAlign;
  if (!M->MediaPresent || !M->LogicalPartition || M->BlockSize != 4096 ||
      (Align > OPEN_RO_CHUNK) || ((Align > 1) && ((Align & (Align - 1)) != 0)) ||
      ((Align > 1) && (((UINTN)Bounce & (Align - 1)) != 0)) ||
      (ExposedBlocks - 1 > M->LastBlock)) { return EFI_UNSUPPORTED; }
  ZeroMem (V, sizeof (*V));
  V->Source = Source; V->Bounce = Bounce; V->SourceMediaId = M->MediaId;
  V->Media = *M;
  V->Media.ReadOnly = TRUE;
  V->Media.WriteCaching = FALSE;
  V->Media.LogicalPartition = FALSE;
  V->Media.IoAlign = 1;
  V->Media.LastBlock = ExposedBlocks - 1;
  V->Io.Revision = Source->Revision;
  V->Io.Media = &V->Media;
  V->Io.Reset = ReadOnlyReset;
  V->Io.ReadBlocks = ReadOnlyRead;
  V->Io.WriteBlocks = ReadOnlyWrite;
  V->Io.FlushBlocks = ReadOnlyFlush;
  return EFI_SUCCESS;
}
