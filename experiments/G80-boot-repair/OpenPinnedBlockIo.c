#include "OpenPinnedBlockIo.h"

STATIC EFI_STATUS EFIAPI
PinnedWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId, EFI_LBA Lba, UINTN Size, VOID *Buffer)
{
 OPEN_PIN_VOLUME *V=(OPEN_PIN_VOLUME *)This;
 EFI_BLOCK_IO_PROTOCOL *Source=V->Ro.Source;
 EFI_STATUS Status;
 UINT8 H[32];UINTN Index;CONST UINT8 *Old,*New;
 if(EFI_ERROR(V->Fault)){return V->Fault;}
 if(!Source->Media->MediaPresent){return EFI_NO_MEDIA;}
 if(MediaId!=V->Ro.Media.MediaId || Source->Media->MediaId!=V->Ro.SourceMediaId || Source->Media->BlockSize!=4096){return EFI_MEDIA_CHANGED;}
 // Only exact 64KiB requests from the pinned updater are admitted. Ordinary
 // filesystem writes and every byte outside the exported 1GiB always refuse.
 if(V->Frozen || Buffer==NULL || Size!=OPEN_PIN_CHUNK || (Lba%16)!=0 || Lba>OPEN_PIN_BLOCKS-16){V->Ro.DeniedWrites++;return EFI_WRITE_PROTECTED;}
 Index=(UINTN)(Lba/16);Old=V->Hashes+Index*64+(V->Undo?32:0);New=V->Hashes+Index*64+(V->Undo?0:32);
 OpenShaAll(Buffer,Size,H);
 if(CompareMem(H,New,32)!=0){V->Ro.DeniedWrites++;V->Fault=EFI_ACCESS_DENIED;return V->Fault;}
 Status=V->Ro.Io.ReadBlocks(&V->Ro.Io,MediaId,Lba,Size,V->Check);
 if(EFI_ERROR(Status)){V->Fault=Status;return Status;}
 OpenShaAll(V->Check,Size,H);
 if(CompareMem(H,New,32)==0){V->AlreadyChunks++;return EFI_SUCCESS;}
 if(CompareMem(H,Old,32)!=0){V->Fault=EFI_COMPROMISED_DATA;return V->Fault;}
 // Pin the complete current chunk, then forward exactly that aligned chunk.
 // A failed/torn write holds the image; never blindly retry an unknown state.
 CopyMem(V->Ro.Bounce,Buffer,Size);
 Status=Source->WriteBlocks(Source,V->Ro.SourceMediaId,Lba,Size,V->Ro.Bounce);
 if(!EFI_ERROR(Status)){Status=Source->FlushBlocks(Source);}
 if(!EFI_ERROR(Status)){Status=V->Ro.Io.ReadBlocks(&V->Ro.Io,MediaId,Lba,Size,V->Check);}
 if(!EFI_ERROR(Status)){OpenShaAll(V->Check,Size,H);if(CompareMem(H,New,32)!=0){Status=EFI_CRC_ERROR;}}
 if(EFI_ERROR(Status)){V->Fault=Status;return Status;}
 V->WrittenChunks++;return EFI_SUCCESS;
}

EFI_STATUS
OpenInitPinnedVolume (OPEN_PIN_VOLUME *V, EFI_BLOCK_IO_PROTOCOL *Source,
 VOID *Dma, VOID *Check, CONST UINT8 *Hashes, BOOLEAN Undo)
{
 EFI_STATUS Status;
 if(V==NULL || Source==NULL || Source->Media==NULL || Source->Media->ReadOnly ||
 Source->WriteBlocks==NULL || Source->FlushBlocks==NULL || Check==NULL || Hashes==NULL ||
 Check==Dma){return EFI_INVALID_PARAMETER;}
 ZeroMem(V,sizeof(*V));
 Status=OpenInitReadOnlyVolume(&V->Ro,Source,Dma,OPEN_PIN_BLOCKS);
 if(EFI_ERROR(Status)){return Status;}
 V->Hashes=Hashes;V->Check=Check;V->Undo=Undo;V->Fault=EFI_SUCCESS;
 // SCSI mode-sense remains protected. Only explicit passthrough commands
 // reach the exact-data gate; no generic writable mass-storage volume exists.
 V->Ro.Io.WriteBlocks=PinnedWrite;return EFI_SUCCESS;
}
