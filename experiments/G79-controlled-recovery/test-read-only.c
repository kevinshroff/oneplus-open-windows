// Exercise the exact facade implementation with an instrumented fake disk.
#define OPEN_RO_TEST
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#define STATIC static
#define EFIAPI
#define VOID void
#define TRUE 1
#define FALSE 0
typedef uint8_t UINT8; typedef uint32_t UINT32; typedef uint64_t UINT64;
typedef uintptr_t UINTN; typedef uint64_t EFI_LBA; typedef uint64_t EFI_STATUS;
typedef unsigned char BOOLEAN;
#define EFI_SUCCESS 0
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

static unsigned reads,writes,resets,flushes,checks;
static void *bounce;
static uint64_t fail_lba = UINT64_MAX;
static unsigned char pattern(uint64_t lba, size_t off) { return (unsigned char)(lba*17+off*3); }
static EFI_STATUS fake_read(EFI_BLOCK_IO_PROTOCOL *s,UINT32 id,EFI_LBA lba,UINTN bytes,VOID *out) {
 assert(id==s->Media->MediaId && bytes==4096 && out==bounce);
 assert(lba<=s->Media->LastBlock && ((uintptr_t)out % s->Media->IoAlign)==0);
 reads++; if(lba==fail_lba)return EFI_DEVICE_ERROR;
 for(size_t j=0;j<bytes;j++)((unsigned char*)out)[j]=pattern(lba,j);
 return EFI_SUCCESS;
}
static EFI_STATUS fake_write(EFI_BLOCK_IO_PROTOCOL *s,UINT32 id,EFI_LBA l,UINTN n,VOID*b) {
 (void)s;(void)id;(void)l;(void)n;(void)b;writes++;return EFI_SUCCESS;
}
static EFI_STATUS fake_reset(EFI_BLOCK_IO_PROTOCOL*s,BOOLEAN b){(void)s;(void)b;resets++;return EFI_SUCCESS;}
static EFI_STATUS fake_flush(EFI_BLOCK_IO_PROTOCOL*s){(void)s;flushes++;return EFI_SUCCESS;}
#define CHECK(c) do {assert(c);checks++;}while(0)
int main(void) {
 EFI_BLOCK_IO_MEDIA m={.MediaId=99,.MediaPresent=TRUE,.LogicalPartition=TRUE,.BlockSize=4096,.IoAlign=4096,.LastBlock=0x43ffff};
 EFI_BLOCK_IO_PROTOCOL src={.Revision=0x2001f,.Media=&m,.Reset=fake_reset,.ReadBlocks=fake_read,.WriteBlocks=fake_write,.FlushBlocks=fake_flush};
 OPEN_RO_VOLUME v; unsigned char *out=malloc(131073); assert(out);
 CHECK(posix_memalign(&bounce,65536,OPEN_RO_CHUNK)==0);
 CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,0x440000)==EFI_SUCCESS);
 CHECK(v.Io.Media==&v.Media && v.Media.ReadOnly && v.Media.IoAlign==1 && !v.Media.WriteCaching);
 for(unsigned blocks=1;blocks<=32;blocks++) {
  uint64_t lba=0x400100+blocks;
  CHECK(v.Io.ReadBlocks(&v.Io,99,lba,blocks*4096,out+1)==EFI_SUCCESS);
  for(unsigned j=0;j<blocks*4096;j++)CHECK(out[j+1]==pattern(lba+j/4096,j%4096));
 }
 unsigned before=reads;
 CHECK(v.Io.ReadBlocks(&v.Io,99,UINT64_MAX,4096,out)==EFI_INVALID_PARAMETER);
 CHECK(v.Io.ReadBlocks(&v.Io,99,0x43ffff,8192,out)==EFI_INVALID_PARAMETER);
 CHECK(v.Io.ReadBlocks(&v.Io,99,0,4095,out)==EFI_BAD_BUFFER_SIZE);
 CHECK(v.Io.ReadBlocks(&v.Io,99,0,4096,NULL)==EFI_INVALID_PARAMETER);
 CHECK(v.Io.ReadBlocks(&v.Io,98,0,4096,out)==EFI_MEDIA_CHANGED);
 CHECK(v.Io.ReadBlocks(&v.Io,99,UINT64_MAX,0,NULL)==EFI_SUCCESS);
 CHECK(reads==before);
 for(unsigned j=0;j<1024;j++) {
  CHECK(v.Io.WriteBlocks(&v.Io,j,UINT64_MAX-j,j,out)==EFI_WRITE_PROTECTED);
  CHECK(v.Io.Reset(&v.Io,TRUE)==EFI_SUCCESS);
  CHECK(v.Io.FlushBlocks(&v.Io)==EFI_SUCCESS);
 }
 CHECK(!writes && !resets && !flushes && v.DeniedWrites==1024);
 CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,0x40000)==EFI_SUCCESS);
 CHECK(v.Io.ReadBlocks(&v.Io,99,0x3ffff,4096,out)==EFI_SUCCESS);
 CHECK(v.Io.ReadBlocks(&v.Io,99,0x40000,4096,out)==EFI_INVALID_PARAMETER);
 m.MediaId++;CHECK(v.Io.ReadBlocks(&v.Io,99,0,4096,out)==EFI_MEDIA_CHANGED);m.MediaId--;
 m.MediaPresent=FALSE;CHECK(v.Io.ReadBlocks(&v.Io,99,0,4096,out)==EFI_NO_MEDIA);m.MediaPresent=TRUE;
 m.LastBlock=2;CHECK(v.Io.ReadBlocks(&v.Io,99,3,4096,out)==EFI_INVALID_PARAMETER);m.LastBlock=0x43ffff;
 fail_lba=5;CHECK(v.Io.ReadBlocks(&v.Io,99,4,12288,out)==EFI_DEVICE_ERROR);CHECK(v.Failures==1);fail_lba=UINT64_MAX;
 CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,0)==EFI_INVALID_PARAMETER);
 CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,0x440001)==EFI_UNSUPPORTED);
 m.BlockSize=512;CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,1)==EFI_UNSUPPORTED);m.BlockSize=4096;
 m.IoAlign=3;CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,1)==EFI_UNSUPPORTED);m.IoAlign=4096;
 CHECK(OpenInitReadOnlyVolume(&v,&src,(char*)bounce+1,1)==EFI_UNSUPPORTED);
 m.LogicalPartition=FALSE;CHECK(OpenInitReadOnlyVolume(&v,&src,bounce,1)==EFI_UNSUPPORTED);
 CHECK(!writes && !resets && !flushes);
 printf("PASS %u checks; source reads=%u writes=%u resets=%u flushes=%u\n",checks,reads,writes,resets,flushes);
 free(out);free(bounce);return 0;
}
