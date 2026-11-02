/* Actual probe C, real UEFI headers, modeled services and metadata only. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#undef NULL
#include "OpenPilFootprint.c"

EFI_GUID gEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
EFI_GUID gEfiGraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GRAPHICS_OUTPUT_PROTOCOL Gops[2];
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE GopModes[2];
static EFI_BOOT_SERVICES Bs;
static EFI_DXE_SERVICES Ds;
static EFI_SYSTEM_TABLE St;
static EFI_RUNTIME_SERVICES Rt;
EFI_BOOT_SERVICES *gBS = &Bs;
EFI_DXE_SERVICES *gDS = &Ds;
EFI_SYSTEM_TABLE *gST = &St;
static ARM_MEMORY_REGION_DESCRIPTOR_EX Platform[2];
static UINT64 HobStorage[1024];
static UINT64 OriginalHobStorage[1024];
static VOID *HobQuery = HobStorage;
static EFI_LOADED_IMAGE_PROTOCOL Images[40];
static EFI_CONFIGURATION_TABLE Configs[40];
static const char *Case;
static char Text[32768];
static size_t Used, Allocations, Frees;
static int Is(const char *name) { return strcmp(Case,name)==0; }

INTN EFIAPI AsciiStrCmp(CONST CHAR8 *a, CONST CHAR8 *b) { return strcmp(a,b); }
VOID *EFIAPI AllocatePool(UINTN n) { if(Is("pool-fail")&&n==MAP_BYTES)return NULL;Allocations++;return calloc(1,n); }
VOID EFIAPI FreePool(VOID *p) { assert(p);Frees++;free(p); }
VOID *EFIAPI GetHobList(VOID) { return Is("hob-null")?NULL:HobQuery; }
ARM_MEMORY_REGION_DESCRIPTOR_EX *GetPlatformMemoryMap(VOID) { return Is("platform-null")?NULL:Platform; }

static void Report(const CHAR8 *f, ...) {
  char fmt[1024];size_t at=0,i;int n;va_list args;
  for(i=0;f[i];i++) {
    assert(at+5<sizeof(fmt));
    if(f[i]=='%'&&f[i+1]=='a') { fmt[at++]='%';fmt[at++]='s';i++; }
    else if(f[i]=='%'&&f[i+1]=='r') { memcpy(fmt+at,"%lx",3);at+=3;i++; }
    else if(f[i]=='%'&&f[i+1]=='g') { memcpy(fmt+at,"%p",2);at+=2;i++; }
    else fmt[at++]=f[i];
  }
  fmt[at]=0;va_start(args,f);n=vsnprintf(Text+Used,sizeof(Text)-Used,fmt,args);va_end(args);
  assert(n>=0&&(size_t)n<sizeof(Text)-Used);Used+=(size_t)n;
}
static EFI_STATUS EFIAPI GcdMap(UINTN *n, EFI_GCD_MEMORY_SPACE_DESCRIPTOR **out) {
  UINTN i, count=Is("gcd-many")?33:1;
  if(Is("gcd-error"))return EFI_DEVICE_ERROR;
  if(Is("gcd-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  if(Is("gcd-empty")){*n=0;*out=NULL;return EFI_SUCCESS;}
  if(Is("gcd-null")){*n=1;*out=NULL;return EFI_SUCCESS;}
  if(Is("gcd-count")){*n=4097;*out=NULL;return EFI_SUCCESS;}
  *out=AllocatePool(count*sizeof(**out));*n=count;
  for(i=0;i<count;i++) {
    (*out)[i].BaseAddress=count==1?POLICY_START:WINDOW_START+i*4096;
    (*out)[i].Length=count==1?POLICY_BYTES:4096;
    (*out)[i].GcdMemoryType=EfiGcdMemoryTypeSystemMemory;(*out)[i].Attributes=EFI_MEMORY_WB;
  }
  if(Is("gcd-overflow")){(*out)[0].BaseAddress=MAX_UINT64-7;(*out)[0].Length=16;}
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI EfiMap(UINTN *bytes, EFI_MEMORY_DESCRIPTOR *map, UINTN *key, UINTN *stride, UINT32 *version) {
  UINTN i,n=Is("efi-many")?33:1,count=n+2;(void)key;
  if(Is("efi-error"))return EFI_DEVICE_ERROR;
  if(Is("efi-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  if(Is("hob-map-duplicate")||Is("scm-map-duplicate"))count++;
  *stride=sizeof(*map);*version=EFI_MEMORY_DESCRIPTOR_VERSION;*bytes=count*sizeof(*map);
  for(i=0;i<n;i++) {
    map[i].PhysicalStart=n==1?POLICY_START:WINDOW_START+i*4096;
    map[i].NumberOfPages=n==1?POLICY_BYTES/4096:1;
    map[i].Type=EfiReservedMemoryType;map[i].Attribute=EFI_MEMORY_WB;
  }
  map[n].PhysicalStart=(UINTN)HobQuery&~4095ULL;
  map[n].NumberOfPages=4;map[n].Type=EfiBootServicesData;map[n].Attribute=EFI_MEMORY_WB;
  if(Is("hob-map-missing"))map[n].PhysicalStart=(UINTN)HobQuery+2*1024*1024;
  if(Is("hob-map-wrong-type"))map[n].Type=EfiConventionalMemory;
  if(Is("hob-storage-header-short")||Is("hob-storage-tail-short")){
    UINTN room=Is("hob-storage-header-short")?16:sizeof(EFI_HOB_HANDOFF_INFO_TABLE)+8;
    /* Explicit short descriptor model, backed by an exactly sized ASan object. */
    map[n].PhysicalStart=(UINTN)HobQuery-(4096-room);map[n].NumberOfPages=1;
  }
  map[n+1].PhysicalStart=0xc510e000;map[n+1].NumberOfPages=1;map[n+1].Type=EfiBootServicesData;map[n+1].Attribute=EFI_MEMORY_WB;
  if(Is("scm-map-readonly"))map[n+1].Attribute|=EFI_MEMORY_RO;
  if(Is("scm-map-missing"))map[n+1].PhysicalStart+=4096;
  if(Is("scm-map-wrong-type"))map[n+1].Type=EfiReservedMemoryType;
  if(Is("hob-map-duplicate"))map[n+2]=map[n];
  if(Is("scm-map-duplicate"))map[n+2]=map[n+1];
  if(Is("efi-empty"))*bytes=0;
  if(Is("efi-zero-stride"))*stride=0;
  if(Is("efi-short-stride"))*stride=8;
  if(Is("efi-large-stride"))*stride=2048;
  if(Is("efi-bad-size"))(*bytes)--;
  if(Is("efi-too-large"))*bytes=MAP_BYTES+1;
  if(Is("efi-version"))*version=0;
  if(Is("efi-overflow")){map[0].PhysicalStart=MAX_UINT64-7;map[0].NumberOfPages=1;}
  if(Is("efi-unreserved"))map[0].Type=EfiConventionalMemory;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI ScmProtocol(EFI_GUID *guid,VOID *registration,VOID **out) {
  assert(guid==&mScmInventory&&registration==NULL);
  if(Is("scm-locate-error"))return EFI_NOT_FOUND;
  if(Is("scm-locate-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  *out=Is("scm-null")?NULL:(VOID *)(UINTN)(Is("scm-pointer-overflow")?MAX_UINTN-31:0xc510e140);
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI ScmDescriptor(EFI_PHYSICAL_ADDRESS address,EFI_GCD_MEMORY_SPACE_DESCRIPTOR *d) {
  assert(address==0xc510e178);
  if(Is("scm-gcd-error"))return EFI_DEVICE_ERROR;
  if(Is("scm-gcd-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  memset(d,0,sizeof(*d));d->BaseAddress=0xc510e000;d->Length=4096;d->GcdMemoryType=EfiGcdMemoryTypeSystemMemory;d->Attributes=EFI_MEMORY_WB;
  if(Is("scm-gcd-overflow")){d->BaseAddress=MAX_UINT64-7;d->Length=16;}
  if(Is("scm-gcd-wrong-type"))d->GcdMemoryType=EfiGcdMemoryTypeMemoryMappedIo;
  if(Is("scm-gcd-short")){d->BaseAddress=address;d->Length=7;}
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI ImageHandles(EFI_LOCATE_SEARCH_TYPE how, EFI_GUID *guid, VOID *search, UINTN *n, EFI_HANDLE **out) {
  UINTN i,count=Is("images-many-overlap")?33:1;(void)how;(void)search;
  if(guid==&gEfiGraphicsOutputProtocolGuid){
    if(Is("gop-error"))return EFI_DEVICE_ERROR;
    if(Is("gop-warning"))return EFI_WARN_UNKNOWN_GLYPH;
    if(Is("gop-null")){*n=1;*out=NULL;return EFI_SUCCESS;}
    if(Is("gop-count")){*n=9;*out=NULL;return EFI_SUCCESS;}
    if(Is("gop-zero")){*n=0;*out=NULL;return EFI_SUCCESS;}
    *n=2;*out=AllocatePool(2*sizeof(**out));
    for(i=0;i<2;i++){(*out)[i]=&Gops[i];Gops[i].Mode=&GopModes[i];GopModes[i].FrameBufferBase=0xb8000000;GopModes[i].FrameBufferSize=0x151c380;}
    if(Is("gop-mode-null"))Gops[0].Mode=NULL;
    if(Is("gop-empty"))GopModes[0].FrameBufferSize=0;
    if(Is("gop-overflow")){GopModes[0].FrameBufferBase=MAX_UINT64-7;GopModes[0].FrameBufferSize=16;}
    if(Is("gop-overlap"))GopModes[0].FrameBufferBase=WINDOW_START;
    return EFI_SUCCESS;
  }
  assert(guid==&gEfiLoadedImageProtocolGuid);
  if(Is("images-error"))return EFI_DEVICE_ERROR;
  if(Is("images-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  if(Is("images-empty")){*n=0;*out=NULL;return EFI_SUCCESS;}
  if(Is("images-null")){*n=1;*out=NULL;return EFI_SUCCESS;}
  if(Is("images-count")){*n=513;*out=NULL;return EFI_SUCCESS;}
  *out=AllocatePool(count*sizeof(**out));*n=count;
  for(i=0;i<count;i++){(*out)[i]=&Images[i];Images[i].ImageBase=(VOID *)(UINTN)(Is("image-overlap")||Is("images-many-overlap")?WINDOW_START:0xc0000000);Images[i].ImageSize=4096;}
  if(Is("image-overflow")){Images[0].ImageBase=(VOID *)(UINTN)(MAX_UINT64-7);Images[0].ImageSize=16;}
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI ImageProtocol(EFI_HANDLE handle, EFI_GUID *guid, VOID **out) {
  if(guid==&gEfiGraphicsOutputProtocolGuid){
    if(Is("gop-protocol-error"))return EFI_DEVICE_ERROR;
    if(Is("gop-protocol-warning"))return EFI_WARN_UNKNOWN_GLYPH;
    *out=Is("gop-protocol-null")?NULL:handle;return EFI_SUCCESS;
  }
  assert(guid==&gEfiLoadedImageProtocolGuid);if(Is("image-error"))return EFI_DEVICE_ERROR;
  if(Is("image-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  *out=Is("image-null")?NULL:handle;return EFI_SUCCESS;
}
static void Hobs(void) {
  EFI_HOB_HANDOFF_INFO_TABLE *phit=(VOID *)HobStorage;
  EFI_HOB_MEMORY_ALLOCATION *a=(VOID *)((UINT8 *)phit+sizeof(*phit));
  EFI_HOB_GENERIC_HEADER *end=(VOID *)((UINT8 *)a+sizeof(*a));
  phit->Header.HobType=EFI_HOB_TYPE_HANDOFF;phit->Header.HobLength=sizeof(*phit);
  phit->EfiEndOfHobList=(UINTN)end;
  a->Header.HobType=EFI_HOB_TYPE_MEMORY_ALLOCATION;a->Header.HobLength=sizeof(*a);
  a->AllocDescriptor.MemoryBaseAddress=POLICY_START;a->AllocDescriptor.MemoryLength=POLICY_BYTES;a->AllocDescriptor.MemoryType=EfiReservedMemoryType;
  end->HobType=EFI_HOB_TYPE_END_OF_HOB_LIST;end->HobLength=sizeof(*end);
  if(Is("hob-first-type"))phit->Header.HobType=0;
  if(Is("hob-bad-length"))a->Header.HobLength=1;
  if(Is("hob-short-alloc"))a->Header.HobLength=8;
  if(Is("hob-no-end"))end->HobType=0;
  if(Is("hob-end-mismatch"))phit->EfiEndOfHobList-=8;
  if(Is("hob-too-far"))phit->EfiEndOfHobList=(UINTN)phit+2*1024*1024;
  if(Is("hob-overflow")){a->AllocDescriptor.MemoryBaseAddress=MAX_UINT64-7;a->AllocDescriptor.MemoryLength=16;}
  if(Is("hob-fv-overflow")){a->Header.HobType=EFI_HOB_TYPE_FV;((EFI_HOB_FIRMWARE_VOLUME *)a)->BaseAddress=MAX_UINT64-7;((EFI_HOB_FIRMWARE_VOLUME *)a)->Length=16;}
  if(Is("hob-relocated")){
    /* The pinned CoreInitializeGcdServices copies the allocation without
       rebasing the PHIT fields. The collector must not follow original_end. */
    memcpy(OriginalHobStorage,HobStorage,sizeof(HobStorage));
    ((EFI_HOB_HANDOFF_INFO_TABLE *)OriginalHobStorage)->EfiEndOfHobList=(UINTN)OriginalHobStorage+((UINTN)end-(UINTN)HobStorage);
    memcpy(HobStorage,OriginalHobStorage,sizeof(HobStorage));
  }
}
int main(int argc,char **argv) {
  int complete;assert(argc==2);Case=argv[1];
  strcpy(Platform[0].Name,"PIL Reserved");Platform[0].Address=POLICY_START;Platform[0].Length=POLICY_BYTES;
  Platform[0].MemoryType=EfiReservedMemoryType;Platform[0].ResourceType=EFI_RESOURCE_SYSTEM_MEMORY;
  if(Is("platform-missing"))strcpy(Platform[0].Name,"Other");
  Bs.GetMemoryMap=EfiMap;Bs.LocateHandleBuffer=ImageHandles;Bs.HandleProtocol=ImageProtocol;Bs.LocateProtocol=ScmProtocol;Ds.GetMemorySpaceMap=GcdMap;Ds.GetMemorySpaceDescriptor=ScmDescriptor;
  St.RuntimeServices=&Rt;St.ConfigurationTable=Configs;St.NumberOfTableEntries=1;Configs[0].VendorTable=(VOID *)(UINTN)0x81a04000;
  if(Is("config-count"))St.NumberOfTableEntries=1025;
  if(Is("config-null"))St.ConfigurationTable=NULL;
  if(Is("config-overlap"))Configs[0].VendorTable=(VOID *)(UINTN)WINDOW_START;
  if(Is("config-many")){St.NumberOfTableEntries=33;for(unsigned i=0;i<33;i++)Configs[i].VendorTable=(VOID *)(UINTN)WINDOW_START;}
  Hobs();
  if(Is("hob-storage-header-short")||Is("hob-storage-tail-short")){
    UINTN room=Is("hob-storage-header-short")?16:sizeof(EFI_HOB_HANDOFF_INFO_TABLE)+8;
    HobQuery=malloc(room);assert(HobQuery);memcpy(HobQuery,HobStorage,room);
  }
  if(Is("hob-map-missing")||Is("hob-map-wrong-type"))HobQuery=(VOID *)(UINTN)0x5000;
  OpenAppendPilFootprint(Report);
  complete=Is("success")||Is("image-overlap")||Is("config-overlap")||Is("efi-unreserved")||Is("duplicate")||Is("hob-relocated")||Is("hob-end-mismatch")||Is("hob-too-far")||Is("scm-map-readonly")||Is("gop-overlap");
  assert(strstr(Text,complete?"P139_DONE queries_complete=1":"P139_DONE queries_complete=0"));
  assert(strstr(Text,"PAS_allowed=0 DMA_ownership=not_proved region_writes=0"));
  if(Is("gop-overlap"))assert(strstr(Text,"overlap=1")&&strstr(Text,"P139_gop_valid_rows=2"));
  if(Is("image-overlap"))assert(strstr(Text,"P139_image_overlaps=1"));
  if(Is("config-overlap"))assert(strstr(Text,"P139_config_pointer "));
  if(Is("efi-unreserved"))assert(strstr(Text,"type=7"));
  if(Is("hob-relocated"))assert(strstr(Text,"P139_hob_count=3")&&strstr(Text,"end=1"));
  if(Is("scm-map-readonly"))assert(strstr(Text,"attr=20008")&&strstr(Text,"table_reads=0 hook_writes=0"));
  if(Is("duplicate")){size_t before=Allocations;OpenAppendPilFootprint(Report);assert(Allocations==before&&strstr(Text,"duplicate_call"));}
  assert(Allocations==Frees);
  if(Is("hob-storage-header-short")||Is("hob-storage-tail-short"))free(HobQuery);
  printf("{\"passed\":true,\"case\":\"%s\",\"queries_complete\":%s,\"report_bytes\":%zu,\"allocations\":%zu,\"native_operations\":0}\n",Case,complete?"true":"false",Used,Allocations);
  return 0;
}
