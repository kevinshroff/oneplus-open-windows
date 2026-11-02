// Native fault-injection harness for the actual firmware migration source.
// All I/O uses five in-memory sectors. No phone or host block device is opened.
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "OpenG80GptTypeMigration.h"
#include "OpenG80GoldenData.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>

_Static_assert(sizeof(OPEN_GPT_TYPE_RESULT)==180,"G16 transaction record ABI");
static UINT8 Disk[5][4096], Corrected[5][4096];
static int Writes, Reads, Flushes, FailWrite=-1, FailFlush=-1, FailReadAfterWrite=-1;
static int Cases;
static EFI_LBA Written[4];
static EFI_BLOCK_IO_MEDIA Media;
static EFI_BLOCK_IO_PROTOCOL Io;
static EFI_PARTITION_INFO_PROTOCOL Info;
static EFI_BOOT_SERVICES Services;
EFI_BOOT_SERVICES *gBS=&Services;

VOID *EFIAPI CopyMem(VOID *d,CONST VOID *s,UINTN n){return memcpy(d,s,n);}
VOID *EFIAPI SetMem(VOID *d,UINTN n,UINT8 v){return memset(d,v,n);}
VOID *EFIAPI ZeroMem(VOID *d,UINTN n){return memset(d,0,n);}
INTN EFIAPI CompareMem(CONST VOID *a,CONST VOID *b,UINTN n){return memcmp(a,b,n);}
VOID *EFIAPI AllocatePool(UINTN n){return malloc(n);}
VOID EFIAPI FreePool(VOID *p){free(p);}

static EFI_STATUS EFIAPI Crc(VOID *p,UINTN n,UINT32 *c){*c=(UINT32)crc32(0,p,n);return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Pages(EFI_ALLOCATE_TYPE type,EFI_MEMORY_TYPE mem,UINTN n,EFI_PHYSICAL_ADDRESS *a){
  void *p=NULL;assert(type==AllocateMaxAddress&&mem==EfiBootServicesData&&*a==MAX_UINT32);
  if(posix_memalign(&p,4096,n*4096))return EFI_OUT_OF_RESOURCES;
  *a=(UINTN)p;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI MockFreePages(EFI_PHYSICAL_ADDRESS p,UINTN n){assert(n>0);free((void *)(UINTN)p);return EFI_SUCCESS;}
static UINT32 U32(const UINT8 *p){UINT32 x;memcpy(&x,p,4);return x;}
static int CopyValid(int h,int a){
  UINT8 b[92];memcpy(b,Disk[h],92);UINT32 saved=U32(b+16);memset(b+16,0,4);
  return crc32(0,b,92)==saved && crc32(0,Disk[a],4096)==U32(Disk[h]+88);
}
static void ValidCopy(void){assert(CopyValid(1,2)||CopyValid(3,4));}
static int Index(EFI_LBA l){for(int i=0;i<5;i++)if(mGoldenGptLba[i]==l)return i;assert(0);return -1;}
static EFI_STATUS EFIAPI Read(EFI_BLOCK_IO_PROTOCOL *i,UINT32 id,EFI_LBA l,UINTN n,VOID *p){
  assert(i==&Io&&id==Media.MediaId&&n==4096&&((UINTN)p%4096)==0);Reads++;
  if(FailReadAfterWrite>0&&Writes==FailReadAfterWrite)return EFI_DEVICE_ERROR;
  memcpy(p,Disk[Index(l)],4096);return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Write(EFI_BLOCK_IO_PROTOCOL *i,UINT32 id,EFI_LBA l,UINTN n,VOID *p){
  assert(i==&Io&&id==Media.MediaId&&n==4096&&((UINTN)p%4096)==0);
  int k=Index(l);assert(k!=0&&Writes<4);ValidCopy();
  if(Writes==FailWrite)return EFI_DEVICE_ERROR;
  Written[Writes++]=l;memcpy(Disk[k],p,4096);ValidCopy();return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Flush(EFI_BLOCK_IO_PROTOCOL *i){assert(i==&Io);Flushes++;return Flushes==FailFlush?EFI_DEVICE_ERROR:EFI_SUCCESS;}
static VOID Log(CONST CHAR8 *format,...){(void)format;}
static void Counters(void){Writes=Reads=Flushes=0;FailWrite=FailFlush=FailReadAfterWrite=-1;memset(Written,0,sizeof Written);}
static void Reset(void){memcpy(Disk,mGoldenGpt,sizeof Disk);Counters();Media.LastBlock=0x7613bff;Media.ReadOnly=FALSE;}
static OPEN_GPT_TYPE_RESULT Run(UINT32 mode){OPEN_GPT_TYPE_RESULT r;OpenRunG80GptTypeMigration(&Io,&Info,mode,Log,&r);Cases++;return r;}
static void Restore(void){Counters();OPEN_GPT_TYPE_RESULT r=Run(14);assert((r.State==2||r.State==3)&&r.Status==0&&OpenG80GptTypeAllowsBoot());assert(!memcmp(Disk,mGoldenGpt,sizeof Disk));ValidCopy();}

int main(int argc,char **argv){
  assert(argc==2);
  const char *names[5]={"protective-mbr","primary-header","primary-entries","backup-header","backup-entries"};
  for(int i=0;i<5;i++){
    char path[2048];snprintf(path,sizeof path,"%s/after/%s.bin",argv[1],names[i]);
    FILE *f=fopen(path,"rb");assert(f);assert(fread(Corrected[i],1,4096,f)==4096);assert(fgetc(f)==EOF);fclose(f);
  }
  memset(&Media,0,sizeof Media);Media.MediaId=0x20736675;Media.MediaPresent=TRUE;Media.BlockSize=4096;Media.IoAlign=4096;
  Io.Media=&Media;Io.ReadBlocks=Read;Io.WriteBlocks=Write;Io.FlushBlocks=Flush;
  Info.Type=PARTITION_TYPE_GPT;Info.Info.Gpt.StartingLBA=0x2208;Info.Info.Gpt.EndingLBA=0x442207;
  memcpy(&Info.Info.Gpt.UniquePartitionGUID,mGoldenGpt[2]+656,16);
  Services.AllocatePages=Pages;Services.FreePages=MockFreePages;Services.CalculateCrc32=Crc;
  Reset();OPEN_GPT_TYPE_RESULT r=Run(13);assert(r.State==3&&r.Status==0&&r.WritesVerified==4&&Writes==4&&Flushes==4);
  assert(!memcmp(Disk,Corrected,sizeof Disk));assert(OpenG80GptTypeAllowsBoot());
  assert(Written[0]==0x7613bfb&&Written[1]==0x7613bff&&Written[2]==2&&Written[3]==1);
  Counters();r=Run(13);assert(r.State==2&&Writes==0);Restore();Counters();r=Run(14);assert(r.State==2&&Writes==0);
  Reset();Disk[0][123]^=1;r=Run(13);assert(r.State==1&&Writes==0&&!OpenG80GptTypeAllowsBoot());
  Reset();Disk[2][1000]^=1;r=Run(13);assert(r.State==1&&Writes==0);
  Reset();Media.LastBlock--;r=Run(13);assert(r.State==1&&Writes==0);
  Reset();Media.ReadOnly=TRUE;r=Run(13);assert(r.State==1&&Writes==0);
  for(int mode=13;mode<=14;mode++)for(int fault=0;fault<3;fault++)for(int cut=0;cut<4;cut++){
    Reset();if(mode==14)memcpy(Disk,Corrected,sizeof Disk);
    if(fault==0)FailWrite=cut;
    else if(fault==1)FailFlush=cut+1;
    else FailReadAfterWrite=cut+1;
    r=Run(mode);assert(r.State==4&&!OpenG80GptTypeAllowsBoot());ValidCopy();
    Restore();
  }
  for(int mask=0;mask<16;mask++)for(int mode=13;mode<=14;mode++){
    Reset();
    for(int k=1;k<=4;k++)if(mask&(1<<(k-1)))memcpy(Disk[k],Corrected[k],4096);
    int valid=CopyValid(1,2)||CopyValid(3,4);
    r=Run(mode);
    if(!valid){assert(r.State==1&&Writes==0&&!OpenG80GptTypeAllowsBoot());continue;}
    assert((r.State==2||r.State==3)&&r.Status==0&&OpenG80GptTypeAllowsBoot());
    assert(!memcmp(Disk,mode==13?Corrected:mGoldenGpt,sizeof Disk));ValidCopy();
  }
  printf("PASS: %d actual-source runs; exact apply/undo, no-op repeat, foreign-sector/geometry/read-only refusal, write/flush/readback fault recovery; >=1 valid GPT copy after every write. all 16 mixed-sector patterns in both directions; Synthetic RAM only.\n",Cases);
  return 0;
}
