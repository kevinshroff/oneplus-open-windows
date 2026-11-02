// Exercise the exact facade implementation with an instrumented fake disk.
#define OPEN_RO_TEST
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#define STATIC static
#define CONST const
#define EFIAPI
#define VOID void
#define TRUE 1
#define FALSE 0
typedef uint8_t UINT8; typedef uint32_t UINT32; typedef uint64_t UINT64;
typedef uintptr_t UINTN; typedef uint64_t EFI_LBA; typedef uint64_t EFI_STATUS;
typedef unsigned char BOOLEAN;
#define EFI_SUCCESS 0
#define EFI_ACCESS_DENIED (0x800000000000000fULL)
#define EFI_CRC_ERROR (0x800000000000001bULL)
#define EFI_COMPROMISED_DATA (0x8000000000000021ULL)
#define CompareMem memcmp
#define EFI_INVALID_PARAMETER (0x8000000000000002ULL)
#define EFI_UNSUPPORTED (0x8000000000000003ULL)
#define EFI_BAD_BUFFER_SIZE (0x8000000000000004ULL)
#define EFI_DEVICE_ERROR (0x8000000000000007ULL)
#define EFI_WRITE_PROTECTED (0x8000000000000008ULL)
#define EFI_NO_MEDIA (0x800000000000000cULL)
#define EFI_MEDIA_CHANGED (0x800000000000000dULL)
#define EFI_ERROR(x) (((x)>>63)!=0)
#define CopyMem memcpy
#define ZeroMem(p,n) memset((p),0,(n))
typedef struct {
 UINT32 MediaId; BOOLEAN RemovableMedia,MediaPresent,LogicalPartition,ReadOnly,WriteCaching;
 UINT32 BlockSize,IoAlign; EFI_LBA LastBlock;
 UINT64 LowestAlignedLba; UINT32 LogicalBlocksPerPhysicalBlock,OptimalTransferLengthGranularity;
} EFI_BLOCK_IO_MEDIA;
typedef struct _BIO EFI_BLOCK_IO_PROTOCOL;
struct _BIO {
 UINT64 Revision; EFI_BLOCK_IO_MEDIA *Media;
 EFI_STATUS (*Reset)(EFI_BLOCK_IO_PROTOCOL*,BOOLEAN);
 EFI_STATUS (*ReadBlocks)(EFI_BLOCK_IO_PROTOCOL*,UINT32,EFI_LBA,UINTN,VOID*);
 EFI_STATUS (*WriteBlocks)(EFI_BLOCK_IO_PROTOCOL*,UINT32,EFI_LBA,UINTN,VOID*);
 EFI_STATUS (*FlushBlocks)(EFI_BLOCK_IO_PROTOCOL*);
};
#include "ReadOnlyBlockIo.c"
#include "OpenPinnedBlockIo.c"
static unsigned checks,reads,writes,flushes;static int failread,failwrite,failflush,corrupt;
static unsigned char current[65536],old[65536],after[65536];static void *dma;
#define CHECK(c) do {assert(c);checks++;}while(0)
static EFI_STATUS readsrc(EFI_BLOCK_IO_PROTOCOL*s,UINT32 id,EFI_LBA l,UINTN n,VOID*b){assert(s->Media->MediaId==id&&n==4096&&b==dma&&l<16);reads++;if(failread)return EFI_DEVICE_ERROR;memcpy(b,current+l*4096,n);return EFI_SUCCESS;}
static EFI_STATUS writesrc(EFI_BLOCK_IO_PROTOCOL*s,UINT32 id,EFI_LBA l,UINTN n,VOID*b){assert(s->Media->MediaId==id&&n==65536&&b==dma&&l==0);writes++;if(failwrite)return EFI_DEVICE_ERROR;memcpy(current,b,n);if(corrupt)current[1024]^=1;return EFI_SUCCESS;}
static EFI_STATUS flushsrc(EFI_BLOCK_IO_PROTOCOL*s){(void)s;flushes++;return failflush?EFI_DEVICE_ERROR:EFI_SUCCESS;}
int main(void){
 EFI_BLOCK_IO_MEDIA m={.MediaId=99,.MediaPresent=TRUE,.LogicalPartition=TRUE,.BlockSize=4096,.IoAlign=4096,.LastBlock=0x71bb90e};
 EFI_BLOCK_IO_PROTOCOL src={.Revision=0x2001f,.Media=&m,.ReadBlocks=readsrc,.WriteBlocks=writesrc,.FlushBlocks=flushsrc};
 OPEN_PIN_VOLUME v;void*check;UINT8*hashes=calloc(OPEN_PIN_COUNT,64);assert(hashes);CHECK(posix_memalign(&dma,65536,65536)==0);CHECK(posix_memalign(&check,65536,65536)==0);
 for(size_t i=0;i<sizeof(old);i++){old[i]=(unsigned char)(i*7);after[i]=(unsigned char)(i*11+5);}OpenShaAll(old,sizeof(old),hashes);OpenShaAll(after,sizeof(after),hashes+32);
 #define INIT(undo) do {failread=failwrite=failflush=corrupt=0;CHECK(OpenInitPinnedVolume(&v,&src,dma,check,hashes,undo)==EFI_SUCCESS);}while(0)
 memcpy(current,old,sizeof(old));INIT(FALSE);CHECK(v.Ro.Media.ReadOnly);unsigned before=writes;
 CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_SUCCESS);CHECK(writes==before+1&&flushes==1&&v.WrittenChunks==1);CHECK(memcmp(current,after,sizeof(after))==0);
 CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_SUCCESS);CHECK(writes==before+1&&v.AlreadyChunks==1);
 INIT(TRUE);CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,old)==EFI_SUCCESS);CHECK(memcmp(current,old,sizeof(old))==0);
 INIT(FALSE);before=writes;for(size_t i=0;i<1024;i++){CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,i,4096,old)==EFI_WRITE_PROTECTED);}CHECK(writes==before&&v.Ro.DeniedWrites==1024);
 CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,1,65536,after)==EFI_WRITE_PROTECTED);CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,UINT64_MAX,65536,after)==EFI_WRITE_PROTECTED);CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,98,0,65536,after)==EFI_MEDIA_CHANGED);CHECK(writes==before);
 INIT(FALSE);unsigned r=reads;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,old)==EFI_ACCESS_DENIED);CHECK(reads==r&&writes==before);
 INIT(FALSE);current[17]^=1;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_COMPROMISED_DATA);CHECK(writes==before);memcpy(current,old,sizeof(old));
 INIT(FALSE);failread=1;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_DEVICE_ERROR);CHECK(writes==before);
 INIT(FALSE);failwrite=1;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_DEVICE_ERROR);before=writes;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_DEVICE_ERROR);CHECK(writes==before);
 INIT(FALSE);failflush=1;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_DEVICE_ERROR);memcpy(current,old,sizeof(old));
 INIT(FALSE);corrupt=1;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_CRC_ERROR);memcpy(current,old,sizeof(old));
 INIT(FALSE);v.Frozen=TRUE;before=writes;r=reads;CHECK(v.Ro.Io.WriteBlocks(&v.Ro.Io,99,0,65536,after)==EFI_WRITE_PROTECTED);CHECK(writes==before&&reads==r);
 CHECK(OpenInitPinnedVolume(&v,&src,dma,dma,hashes,FALSE)==EFI_INVALID_PARAMETER);
 printf("PASS %u checks; exact-source forward/inverse, idempotence, range/data/media refusals, read/write/flush/readback failure holds\n",checks);
 free(check);free(dma);free(hashes);return 0;
}
