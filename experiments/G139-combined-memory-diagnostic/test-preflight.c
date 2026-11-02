/* Execute the actual C adapter with explicit UEFI/filesystem service models.
 * No FAT implementation, physical disk, ACPI installation or DSP runs here.
 * Relevant metadata and all file payloads come from the private G118 capture;
 * bytes outside captured regions are zero padding in the block-service model.
 */
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#define OPEN_ADSP_BINDINGS "TestAdspInputs.h"
#include "OpenAdspPreflight.c"

EFI_GUID gEfiBlockIoProtocolGuid = EFI_BLOCK_IO_PROTOCOL_GUID;
EFI_GUID gEfiDevicePathProtocolGuid = EFI_DEVICE_PATH_PROTOCOL_GUID;
EFI_GUID gEfiSimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
EFI_GUID gEfiAcpiTableProtocolGuid = EFI_ACPI_TABLE_PROTOCOL_GUID;
EFI_GUID gEfiFileInfoGuid = EFI_FILE_INFO_ID;
static EFI_BOOT_SERVICES Bs;
static EFI_DXE_SERVICES Ds;
EFI_BOOT_SERVICES *gBS = &Bs;
EFI_DXE_SERVICES *gDS = &Ds;
static EFI_BLOCK_IO_PROTOCOL RootIo, ChildIo;
static EFI_BLOCK_IO_MEDIA RootMedia, ChildMedia;
static UINT8 RootPath[24], ChildPath[66], Record[128], GptHeader[4096], GptArray[4096];
static UINT8 *Metadata[6];
static UINTN MetadataSizes[6], SourceWrites, ClosedFiles, OpenedFiles, RootClosed;
static UINTN Disconnects, Uninstalls, FreedLive, InstallReports, ReportBytes;
static UINT8 *Published;
static OPEN_ADSP_VOLUME *Facade;
static char *Capture, *Fixture;
static const char *Case;
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL Fs;
static EFI_ACPI_TABLE_PROTOCOL Acpi;
static int RootToken, ChildToken, DuplicateToken, VirtualToken;
static ARM_MEMORY_REGION_DESCRIPTOR_EX Map[3];

typedef struct { EFI_FILE_PROTOCOL Io; FILE *File; UINTN Index; BOOLEAN IsRoot; } MODEL_FILE;
static MODEL_FILE FileRoot;
static int Is(const char *s) { return strcmp(Case,s)==0; }
static UINTN FootprintCalls;
VOID OpenAppendKernelFootprint(OPEN_KERNEL_REPORT r) { assert(++FootprintCalls==1); r("OPEN-KERNEL-FOOTPRINT G131 modeled collection\n"); }
static UINTN ProbeCalls;
static BOOLEAN ProbeReady;
static UINTN PilInventoryCalls;
EFI_STATUS OpenRunPilInventory(VOID){
 assert(++PilInventoryCalls==1 && FootprintCalls==1 && ProbeCalls==0 && Facade==NULL && Disconnects==0 && Uninstalls==0);
 return Is("inventory-publication-error")?EFI_DEVICE_ERROR:EFI_SUCCESS;
}

EFI_STATUS OpenRunPilMetadataProbe(BOOLEAN ready) {
  assert(++ProbeCalls==1 && Disconnects==0 && Uninstalls==0);
  ProbeReady=ready;
  if(ready)assert(Facade && Facade->Handle==&VirtualToken &&
    Facade->Ro.Media.ReadOnly && Facade->Ro.DeniedWrites==0 &&
    Facade->Ro.Failures==0 && ClosedFiles==64 && RootClosed==1 &&
    Facade->Ro.Bounce!=NULL && OpenedFiles==ClosedFiles);
  return Is("probe-publication-error")?EFI_DEVICE_ERROR:EFI_SUCCESS;
}
static UINTN DspCalls,Stopped;static BOOLEAN DspReady;static G136_REPORT DspResult;static jmp_buf StopJump;
CONST G136_REPORT *OpenGetGuardedAdspReport(VOID){return &DspResult;}
EFI_STATUS OpenRunGuardedAdsp(BOOLEAN ready,OPEN_KERNEL_REPORT log,BOOLEAN *mayContinue){
 assert(++DspCalls==1&&ProbeCalls==1&&Disconnects==0&&Uninstalls==0);DspReady=ready;
 if(ready)assert(ProbeReady&&Facade&&Facade->Ro.Media.ReadOnly&&ClosedFiles==64&&RootClosed==1);
 DspResult.PilRequests=ready?1:0;*mayContinue=!Is("DSP-fatal-restore");
 log("G136 model ready=%u\n",ready);return Is("DSP-result-error")?EFI_DEVICE_ERROR:EFI_SUCCESS;
}
UINTN EFIAPI Print(CONST CHAR16 *fmt,...){(void)fmt;return 0;}
VOID EFIAPI CpuDeadLoop(VOID){Stopped++;longjmp(StopJump,1);}
VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { return memmove(d,s,n); }
VOID *EFIAPI SetMem(VOID *d, UINTN n, UINT8 v) { return memset(d,v,n); }
VOID *EFIAPI ZeroMem(VOID *d, UINTN n) { return memset(d,0,n); }
INTN EFIAPI CompareMem(CONST VOID *a, CONST VOID *b, UINTN n) { return memcmp(a,b,n); }
BOOLEAN EFIAPI CompareGuid(CONST GUID *a, CONST GUID *b) { return memcmp(a,b,16)==0; }
INTN EFIAPI AsciiStrCmp(CONST CHAR8 *a, CONST CHAR8 *b) { return strcmp(a,b); }
UINT64 EFIAPI LShiftU64(UINT64 a,UINTN n) { return a<<n; }
VOID *EFIAPI AllocatePool(UINTN n) { return malloc(n); }
VOID *EFIAPI AllocateZeroPool(UINTN n) { return calloc(1,n); }
VOID EFIAPI FreePool(VOID *p) {
  if(Facade && (p==Facade || p==Facade->Path) &&
      (Is("disconnect-error") || Is("uninstall-error") || Is("partial-install"))) { FreedLive++; }
  if (p==Facade) { Facade=NULL; }
  free(p);
}
VOID *EFIAPI AllocateAlignedPages(UINTN n,UINTN a) { void *p=NULL;assert(posix_memalign(&p,a,n*4096)==0);return p; }
VOID EFIAPI FreeAlignedPages(VOID *p,UINTN n) {
  (void)n;
  if(Facade && p==Facade->Ro.Bounce &&
      (Is("disconnect-error") || Is("uninstall-error") || Is("partial-install"))) { FreedLive++; }
  free(p);
}
UINTN EFIAPI AsciiVSPrint(CHAR8 *d,UINTN n,CONST CHAR8 *f,VA_LIST v) {
  char fmt[512];size_t at=0,i;
  for(i=0;f[i]&&at<sizeof(fmt)-4;i++) {
    if(f[i]=='%'&&f[i+1]=='a') { fmt[at++]='%';fmt[at++]='s';i++; }
    else if(f[i]=='%'&&f[i+1]=='r') { memcpy(fmt+at,"%llx",4);at+=4;i++; }
    else { fmt[at++]=f[i]; }
  }
  fmt[at]=0;int z=vsnprintf(d,n,fmt,v);assert(z>=0);return (UINTN)z<n?(UINTN)z:n-1;
}
EFI_DEVICE_PATH_PROTOCOL *EFIAPI DevicePathFromHandle(EFI_HANDLE h) {
  if(h==&RootToken)return(VOID*)RootPath;
  if(h==&ChildToken || h==&DuplicateToken)return(VOID*)ChildPath;
  if(h==&VirtualToken)return Facade->Path;
  return NULL;
}
UINTN EFIAPI GetDevicePathSize(CONST EFI_DEVICE_PATH_PROTOCOL *p) {
  UINTN n=0;for(int i=0;i<64;i++){UINT16 z;memcpy(&z,p->Length,2);assert(z>=4);n+=z;if(p->Type==END_DEVICE_PATH_TYPE&&p->SubType==END_ENTIRE_DEVICE_PATH_SUBTYPE)return n;p=(VOID*)((UINT8*)p+z);}abort();
}
EFI_DEVICE_PATH_PROTOCOL *EFIAPI AppendDevicePathNode(CONST EFI_DEVICE_PATH_PROTOCOL *p,CONST EFI_DEVICE_PATH_PROTOCOL *node) {
  UINTN n=GetDevicePathSize(p);UINT16 z;memcpy(&z,node->Length,2);UINT8 *q=malloc(n+z);memcpy(q,p,n-4);memcpy(q+n-4,node,z);q[n+z-4]=END_DEVICE_PATH_TYPE;q[n+z-3]=END_ENTIRE_DEVICE_PATH_SUBTYPE;q[n+z-2]=4;q[n+z-1]=0;return(VOID*)q;
}
UINT16 EFIAPI SetDevicePathNodeLength(VOID *node,UINTN n) { assert(n<=65535);UINT16 z=n;memcpy((UINT8*)node+2,&z,2);return z; }
ARM_MEMORY_REGION_DESCRIPTOR_EX *GetPlatformMemoryMap(VOID) { return Map; }

static UINT8 *ReadFile(const char *name,UINTN *bytes) {
  char path[2048];snprintf(path,sizeof(path),"%s/%s",strncmp(name,"test-gpt-",9)==0?Fixture:Capture,name);FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>=0);rewind(f);UINT8 *p=malloc((size_t)n+1);assert(fread(p,1,n,f)==(size_t)n);fclose(f);*bytes=n;return p;
}
static EFI_STATUS EFIAPI DiskRead(EFI_BLOCK_IO_PROTOCOL *io,UINT32 id,EFI_LBA lba,UINTN n,VOID *buf) {
  assert(id==io->Media->MediaId && n%4096==0 && lba+n/4096<=io->Media->LastBlock+1);
  if(io==&RootIo){if(lba==1&&n==4096)memcpy(buf,GptHeader,n);else {assert(lba==2&&n==4096);memcpy(buf,GptArray,n);}if(Is("parent-hash"))((UINT8*)buf)[0]^=1;return EFI_SUCCESS;}
  assert(io==&ChildIo);if(Is("source-read-error"))return EFI_DEVICE_ERROR;
  memset(buf,0,n);UINT64 begin=lba*4096,end=begin+n;
  for(UINTN i=0;i<ARRAY_SIZE(mAdspMetadata);i++){UINT64 a=mAdspMetadata[i].Offset,b=a+MetadataSizes[i];if(a<end&&b>begin){UINT64 lo=a>begin?a:begin,hi=b<end?b:end;memcpy((UINT8*)buf+lo-begin,Metadata[i]+lo-a,hi-lo);}}
  if(Is("metadata-hash"))((UINT8*)buf)[0]^=1;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI DiskWrite(EFI_BLOCK_IO_PROTOCOL *i,UINT32 m,EFI_LBA l,UINTN n,VOID *b) { (void)i;(void)m;(void)l;(void)n;(void)b;SourceWrites++;return EFI_DEVICE_ERROR; }
static EFI_STATUS EFIAPI Locate(EFI_LOCATE_SEARCH_TYPE t,EFI_GUID *g,VOID *key,UINTN *n,EFI_HANDLE **h) {
  assert(t==ByProtocol&&CompareGuid(g,&gEfiBlockIoProtocolGuid)&&key==NULL);*n=Is("duplicate-label")?3:2;*h=malloc(*n*sizeof(**h));(*h)[0]=&RootToken;(*h)[1]=&ChildToken;if(*n==3)(*h)[2]=&DuplicateToken;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Handle(EFI_HANDLE h,EFI_GUID *g,VOID **p) {
  *p=NULL;if(h==&RootToken&&CompareGuid(g,&gEfiBlockIoProtocolGuid)){*p=&RootIo;return EFI_SUCCESS;}
  if(h==&ChildToken || h==&DuplicateToken){if(CompareGuid(g,&gEfiBlockIoProtocolGuid))*p=&ChildIo;else if(CompareGuid(g,&mRecordGuid))*p=Record;else if(CompareGuid(g,&mTypeGuid))*p=(VOID*)&mBasicDataGuid;}
  if(h==&VirtualToken&&CompareGuid(g,&gEfiSimpleFileSystemProtocolGuid)&&!Is("no-filesystem"))*p=&Fs;
  return *p?EFI_SUCCESS:EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI LocateProtocol(EFI_GUID *g,VOID *registration,VOID **p) {
  assert(registration==NULL);*p=NULL;if(CompareGuid(g,&mPilGuid)){*p=&Fs;return EFI_SUCCESS;}if(CompareGuid(g,&gEfiAcpiTableProtocolGuid)){*p=&Acpi;return EFI_SUCCESS;}return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI Install(EFI_HANDLE *h,...) {
  VA_LIST ap;EFI_GUID *g;VOID *p;VA_START(ap,h);
  while((g=VA_ARG(ap,EFI_GUID*))!=NULL){p=VA_ARG(ap,VOID*);if(CompareGuid(g,&gEfiBlockIoProtocolGuid))Facade=p;}
  VA_END(ap);assert(Facade&&Facade->Ro.Media.ReadOnly&&Facade->Ro.Media.LogicalPartition&&LabelIs(Facade->Record,"adsp_ro"));
  if(Is("install-error"))return EFI_OUT_OF_RESOURCES;*h=&VirtualToken;return Is("partial-install")?EFI_DEVICE_ERROR:EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Uninstall(EFI_HANDLE h,...) { assert(h==&VirtualToken);Uninstalls++;return Is("uninstall-error")?EFI_DEVICE_ERROR:EFI_SUCCESS; }
static EFI_STATUS EFIAPI Connect(EFI_HANDLE h,EFI_HANDLE *drivers,EFI_DEVICE_PATH_PROTOCOL *path,BOOLEAN recursive) {
  assert(h==&VirtualToken&&!drivers&&!path&&recursive);
  if(Is("write-attempt"))assert(Facade->Ro.Io.WriteBlocks(&Facade->Ro.Io,1,0,4096,GptHeader)==EFI_WRITE_PROTECTED);
  if(Is("read-budget"))Facade->RequestedBytes=READ_LIMIT;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Disconnect(EFI_HANDLE h,EFI_HANDLE driver,EFI_HANDLE child) { assert(h==&VirtualToken&&!driver&&!child);Disconnects++;return Is("disconnect-error")?EFI_DEVICE_ERROR:EFI_SUCCESS; }
static EFI_STATUS EFIAPI GetGcd(UINTN *n,EFI_GCD_MEMORY_SPACE_DESCRIPTOR **d) {
  *n=1;*d=calloc(1,sizeof(**d));(*d)->BaseAddress=0x8A800000;(*d)->Length=0x18A80000;(*d)->GcdMemoryType=Is("gcd-type")?EfiGcdMemoryTypeSystemMemory:EfiGcdMemoryTypeReserved;if(Is("gcd-gap"))(*d)->BaseAddress=ADSP_START+4096;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI GetMap(UINTN *n,EFI_MEMORY_DESCRIPTOR *d,UINTN *key,UINTN *stride,UINT32 *version) {
  assert(*n>=sizeof(*d));*n=sizeof(*d);*key=1;*stride=sizeof(*d);*version=1;memset(d,0,sizeof(*d));d->Type=Is("efi-type")?EfiConventionalMemory:EfiReservedMemoryType;d->PhysicalStart=0x8A800000;d->NumberOfPages=0x18A80000/4096;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Publish(EFI_ACPI_TABLE_PROTOCOL *this,VOID *table,UINTN n,UINTN *key) {
  assert(this==&Acpi);UINT8 sum=0;for(UINTN i=0;i<n;i++)sum+=((UINT8*)table)[i];assert(sum==0);EFI_ACPI_DESCRIPTION_HEADER *h=(VOID*)table;assert(h->Signature==SIGNATURE_32('O','A','P','F')&&h->Length==n&&memcmp(&h->OemTableId,"G119PFLT",8)==0);Published=malloc(n+1);memcpy(Published,table,n);Published[n]=0;ReportBytes=n;InstallReports++;*key=1;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Close(EFI_FILE_PROTOCOL *io) {MODEL_FILE *f=(VOID*)io;if(f->IsRoot){RootClosed++;return Is("root-close")?EFI_DEVICE_ERROR:EFI_SUCCESS;}ClosedFiles++;fclose(f->File);free(f);return Is("file-close")?EFI_DEVICE_ERROR:EFI_SUCCESS;}
static EFI_STATUS EFIAPI Read(EFI_FILE_PROTOCOL *io,UINTN *n,VOID *buffer) {MODEL_FILE *f=(VOID*)io;assert(!f->IsRoot);if(Is("read-error"))return EFI_DEVICE_ERROR;size_t got=fread(buffer,1,*n,f->File);if(Is("short-read")&&got>0)got--;if(Is("extra-eof")&&got==0){got=1;((UINT8*)buffer)[0]=1;}if(Is("file-hash")&&got>0)((UINT8*)buffer)[0]^=1;*n=got;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Info(EFI_FILE_PROTOCOL *io,EFI_GUID *g,UINTN *n,VOID *buffer) {MODEL_FILE *f=(VOID*)io;assert(CompareGuid(g,&gEfiFileInfoGuid)&&*n>=SIZE_OF_EFI_FILE_INFO);if(Is("get-info"))return EFI_DEVICE_ERROR;EFI_FILE_INFO *i=buffer;memset(i,0,SIZE_OF_EFI_FILE_INFO);i->Size=SIZE_OF_EFI_FILE_INFO;i->FileSize=mAdspFiles[f->Index].Bytes;if(Is("file-size"))i->FileSize++;if(Is("file-directory"))i->Attribute=EFI_FILE_DIRECTORY;*n=SIZE_OF_EFI_FILE_INFO;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Open(EFI_FILE_PROTOCOL *root,EFI_FILE_PROTOCOL **out,CHAR16 *path,UINT64 mode,UINT64 attr) {
  assert(root==&FileRoot.Io&&mode==EFI_FILE_MODE_READ&&attr==0);if(Is("open-error"))return EFI_NOT_FOUND;char name[128];for(int i=0;i<128;i++){assert(path[i]<128);name[i]=(char)path[i];if(!name[i])break;}assert(strncmp(name,"\\image\\",7)==0);UINTN idx;for(idx=0;idx<ARRAY_SIZE(mAdspFiles);idx++)if(strcmp(name+7,mAdspFiles[idx].Name)==0)break;assert(idx<ARRAY_SIZE(mAdspFiles));char p[2048];snprintf(p,sizeof(p),"%s/firmware/image/%s",Capture,name+7);MODEL_FILE *f=calloc(1,sizeof(*f));f->File=fopen(p,"rb");assert(f->File);f->Index=idx;f->Io.Close=Close;f->Io.Read=Read;f->Io.GetInfo=Info;*out=&f->Io;OpenedFiles++;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI OpenVolume(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *this,EFI_FILE_PROTOCOL **root) {assert(this==&Fs);if(Is("open-volume"))return EFI_DEVICE_ERROR;*root=&FileRoot.Io;return EFI_SUCCESS;}

int main(int argc,char **argv) {
  assert(argc==4);Capture=argv[1];Fixture=argv[2];Case=argv[3];UINTN n;UINT8 *data=ReadFile("test-gpt-header.bin",&n);assert(n==4096);memcpy(GptHeader,data,n);free(data);data=ReadFile("test-gpt-array.bin",&n);assert(n==4096);memcpy(GptArray,data,n);free(data);
  for(UINTN i=0;i<6;i++){char p[64];snprintf(p,sizeof(p),"metadata/%03u.bin",(unsigned)i);Metadata[i]=ReadFile(p,&MetadataSizes[i]);assert(MetadataSizes[i]==mAdspMetadata[i].Bytes);}
  RootMedia.MediaId=ChildMedia.MediaId=1;RootMedia.MediaPresent=ChildMedia.MediaPresent=TRUE;RootMedia.BlockSize=ChildMedia.BlockSize=4096;RootMedia.LastBlock=SOURCE_DISK_BYTES/4096-1;ChildMedia.LastBlock=SOURCE_BYTES/4096-1;ChildMedia.LogicalPartition=TRUE;if(Is("source-size"))ChildMedia.LastBlock--;RootIo.Media=&RootMedia;ChildIo.Media=&ChildMedia;RootIo.ReadBlocks=ChildIo.ReadBlocks=DiskRead;ChildIo.WriteBlocks=DiskWrite;
  RootPath[0]=HARDWARE_DEVICE_PATH;RootPath[1]=HW_VENDOR_DP;RootPath[2]=20;RootPath[20]=END_DEVICE_PATH_TYPE;RootPath[21]=END_ENTIRE_DEVICE_PATH_SUBTYPE;RootPath[22]=4;memcpy(ChildPath,RootPath,20);ChildPath[20]=MEDIA_DEVICE_PATH;ChildPath[21]=MEDIA_HARDDRIVE_DP;ChildPath[22]=42;ChildPath[62]=END_DEVICE_PATH_TYPE;ChildPath[63]=END_ENTIRE_DEVICE_PATH_SUBTYPE;ChildPath[64]=4;if(Is("parent-path"))ChildPath[4]^=1;
  memcpy(Record,&mBasicDataGuid,16);memcpy(Record+16,&mSourcePartitionGuid,16);UINT64 lo=SOURCE_START,hi=SOURCE_END;memcpy(Record+32,&lo,8);memcpy(Record+40,&hi,8);for(int i=0;i<7;i++){UINT16 c="modem_a"[i];memcpy(Record+56+2*i,&c,2);}
  strcpy(Map[0].Name,"PIL Reserved");Map[0].Address=0x8A800000;Map[0].Length=0x18A80000;Map[0].ResourceType=EFI_RESOURCE_MEMORY_RESERVED;Map[0].ResourceAttribute=EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE;Map[0].MemoryType=EfiReservedMemoryType;Map[0].ArmAttributes=ARM_MEMORY_REGION_ATTRIBUTE_UNCACHED_UNBUFFERED;strcpy(Map[1].Name,"Display Demura");Map[1].Address=ADSP_END;Map[1].Length=0x02300000;Map[1].MemoryType=EfiReservedMemoryType;if(Is("compiled-map"))Map[0].Length-=4096;if(Is("compiled-cache"))Map[0].ArmAttributes=ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK;
  Bs.LocateHandleBuffer=Locate;Bs.HandleProtocol=Handle;Bs.LocateProtocol=LocateProtocol;Bs.InstallMultipleProtocolInterfaces=Install;Bs.UninstallMultipleProtocolInterfaces=Uninstall;Bs.ConnectController=Connect;Bs.DisconnectController=Disconnect;Bs.GetMemoryMap=GetMap;Ds.GetMemorySpaceMap=GetGcd;Fs.OpenVolume=OpenVolume;Acpi.InstallAcpiTable=Publish;FileRoot.IsRoot=TRUE;FileRoot.Io.Open=Open;FileRoot.Io.Close=Close;
  if(!setjmp(StopJump))OpenRunAdspPreflight();assert(InstallReports==1&&SourceWrites==0&&FreedLive==0);char *text=(char*)Published+sizeof(EFI_ACPI_DESCRIPTION_HEADER);assert(strstr(text,"DSP_start=memory_error_diagnostic PIL_request_count="));
  BOOLEAN file_ok=strstr(text,"FINAL file_status=0 ")!=NULL;BOOLEAN mem_ok=strstr(text,"memory_status=0 ")!=NULL;
  BOOLEAN memory_case=Is("compiled-map")||Is("compiled-cache")||Is("gcd-type")||Is("gcd-gap")||Is("efi-type");
  assert(FootprintCalls==1);
  assert(ProbeCalls==1&&DspCalls==1);
  assert(PilInventoryCalls==1);
  assert(DspReady==((Is("success")||Is("inventory-publication-error"))||Is("disconnect-error")||Is("uninstall-error")||Is("DSP-result-error")||Is("DSP-fatal-restore")));
  assert(Stopped==Is("DSP-fatal-restore"));
  assert(ProbeReady==((Is("success")||Is("inventory-publication-error"))||Is("disconnect-error")||Is("uninstall-error")||Is("probe-publication-error")||Is("DSP-result-error")||Is("DSP-fatal-restore")));
  assert(file_ok==((Is("success")||Is("inventory-publication-error"))||Is("probe-publication-error")||Is("DSP-result-error")||Is("DSP-fatal-restore")||memory_case));assert(mem_ok==!memory_case);assert(OpenedFiles==ClosedFiles);if(OpenedFiles)assert(RootClosed==1);
  if(Is("disconnect-error"))assert(Disconnects==1&&Uninstalls==0);if(Is("uninstall-error"))assert(Disconnects==1&&Uninstalls==1);
  printf("{\"case\":\"%s\",\"file_ok\":%s,\"memory_ok\":%s,\"source_writes\":%u,\"files_closed\":%u,\"freed_live_contexts\":%u,\"report_bytes\":%u}\n",Case,file_ok?"true":"false",mem_ok?"true":"false",(unsigned)SourceWrites,(unsigned)ClosedFiles,(unsigned)FreedLive,(unsigned)ReportBytes);
  return 0;
}
