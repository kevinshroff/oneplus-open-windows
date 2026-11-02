/* Actual diagnostic source; ARM64 helpers and UEFI services are explicit models. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#define OPEN_G128_TEST_CALLS
#include "OpenPilMetadataProbe.c"
EFI_GUID gEfiLoadedImageProtocolGuid=EFI_LOADED_IMAGE_PROTOCOL_GUID;
EFI_GUID gEfiAcpiTableProtocolGuid=EFI_ACPI_TABLE_PROTOCOL_GUID;
EFI_GUID gEfiMemoryAttributeProtocolGuid=EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
static EFI_BOOT_SERVICES Bs;
EFI_BOOT_SERVICES *gBS=&Bs;
static EFI_LOADED_IMAGE_PROTOCOL Loaded[2];
static EFI_MEMORY_ATTRIBUTE_PROTOCOL Memory;
static EFI_ACPI_TABLE_PROTOCOL Acpi;
static int Tokens[3];
static UINT8 *Images[2],*Cfgs[2],*Mdts[2];
static UINTN CfgSizes[2],MdtSizes[2],ImageSizes[2],GetCalls,MetaCalls,HeaderCalls,Releases,CachedFrees,Published;
static VOID *Uncached[2];static CONST CHAR8 *Case;static UINT32 Variant;
static UINT8 *PublishedData;static UINTN PublishedSize;
static int Is(CONST char *s){return strcmp(Case,s)==0;}
VOID *EFIAPI CopyMem(VOID *d,CONST VOID *s,UINTN n){return memmove(d,s,n);}
VOID *EFIAPI ZeroMem(VOID *d,UINTN n){return memset(d,0,n);}
INTN EFIAPI CompareMem(CONST VOID *a,CONST VOID *b,UINTN n){return memcmp(a,b,n);}
static int Guid(CONST EFI_GUID *a,CONST EFI_GUID *b){return !memcmp(a,b,16);}
VOID *EFIAPI AllocatePool(UINTN n){return Is("hash-allocation")&&n==mPilImage.TextBytes?NULL:malloc(n);}
VOID *EFIAPI AllocateZeroPool(UINTN n){return Is("report-allocation")?NULL:calloc(1,n);}
VOID EFIAPI FreePool(VOID *p){free(p);}
static UINT8 *Read(CONST char *root,CONST char *name,UINTN *size){char path[2048];snprintf(path,sizeof(path),"%s/%s",root,name);FILE*f=fopen(path,"rb");assert(f);fseek(f,0,SEEK_END);long n=ftell(f);assert(n>=0);rewind(f);UINT8*p=malloc(n);assert(fread(p,1,n,f)==(size_t)n&&!fclose(f));*size=n;return p;}
static UINT32 Id(VOID *cfg){UINT32 v;CopyMem(&v,(UINT8*)cfg+0xec,4);assert(v==1||v==36);return v==36?0:1;}
UINT64 GetCfg(UINTN fn,CHAR16 *name,VOID *out){
 assert(fn==(UINTN)Images[0]+0x17e8);UINTN i=name[9]=='_'?0:1;
 /* Name lengths are13 for FULL_ADSP_DTB and9 for FULL_ADSP. */
 UINTN len=0;while(name[len])len++;i=len==13?0:1;assert(len==13||len==9);GetCalls++;
 if(Is("config-warning")&&i==0)return 5;
 CopyMem(out,Cfgs[i],568);if(Is("config-data")&&i==0)((UINT8*)out)[0x100]^=1;return 0;
}
UINT64 LoadMeta(UINTN fn,UINT64 *ctx){
 assert(fn==(UINTN)Images[0]+0x3144);UINT32 i=Id((VOID*)(UINTN)ctx[0]);UINT64 *state=(VOID*)(UINTN)ctx[1];MetaCalls++;
 if(Is("metadata-error")&&i==0)return 3;
 state[6]=(UINTN)malloc(MdtSizes[i]);CopyMem((VOID*)(UINTN)state[6],Mdts[i],MdtSizes[i]);
 if(Is("metadata-partial")&&i==0)return 8;
 state[7]=(UINTN)malloc(MdtSizes[i]);Uncached[i]=(VOID*)(UINTN)state[7];CopyMem(Uncached[i],Mdts[i],MdtSizes[i]);
 if(Is("cached-hash")&&i==0)((UINT8*)(UINTN)state[6])[0]^=1;
 if(Is("uncached-hash")&&i==0)((UINT8*)Uncached[i])[0]^=1;
 return 0;
}
UINT64 Header(UINTN fn,UINT64 *ctx,VOID *data){
 assert(fn==(UINTN)Images[0]+0x2200);UINT32 i=Id((VOID*)(UINTN)ctx[0]);UINT64*state=(VOID*)(UINTN)ctx[1];assert(data==(VOID*)(UINTN)state[6]);HeaderCalls++;
 state[4]=(UINTN)malloc(52);if(Is("header-error")&&i==0)return 1;state[3]=(UINTN)malloc(64);return 0;
}
VOID Release(UINTN fn,VOID *p){
 assert(fn==(UINTN)Images[0]+0xfcd4);UINTN i=p==Uncached[0]?0:1;assert(p==Uncached[i]);Releases++;
 if(Is("uncached-short-release"))SetQ(Images[0]+0x1b228,Q(Images[0]+0x1b228)+1);
 else if(!Is("uncached-release"))SetQ(Images[0]+0x1b228,Q(Images[0]+0x1b228)+((MdtSizes[i]+4095)&~4095ULL));
 free(p);Uncached[i]=NULL;
}
static EFI_STATUS EFIAPI FreeCached(VOID *p){CachedFrees++;if(Is("pool-free")){free(p);return EFI_DEVICE_ERROR;}free(p);return 0;}
static EFI_STATUS EFIAPI Locate(EFI_LOCATE_SEARCH_TYPE type,EFI_GUID *guid,VOID *key,UINTN *count,EFI_HANDLE **handles){
 assert(type==ByProtocol&&Guid(guid,&gEfiLoadedImageProtocolGuid)&&!key);
 if(Is("image-enumeration"))return EFI_DEVICE_ERROR;
 *count=Is("too-many-images")?257:Is("duplicate-image")?3:2;*handles=calloc(*count,sizeof(**handles));
 (*handles)[0]=&Tokens[0];(*handles)[1]=&Tokens[1];if(*count==3)(*handles)[2]=&Tokens[2];return 0;
}
static EFI_STATUS EFIAPI Handle(EFI_HANDLE h,EFI_GUID *guid,VOID **out){assert(Guid(guid,&gEfiLoadedImageProtocolGuid));*out=h==&Tokens[0]||h==&Tokens[2]?&Loaded[0]:&Loaded[1];return 0;}
static EFI_STATUS EFIAPI LocateProto(EFI_GUID *guid,VOID *key,VOID **out){
 assert(!key);*out=NULL;
 if(Guid(guid,&mPil)){if(Is("no-PIL"))return EFI_NOT_FOUND;*out=Images[0]+0x16188;}
 else if(Guid(guid,&mScm)){if(Is("no-SCM"))return EFI_NOT_FOUND;*out=Images[1]+(Variant?0xe140:0xe0e8);}
 else if(Guid(guid,&gEfiMemoryAttributeProtocolGuid)){if(Is("no-attributes"))return EFI_NOT_FOUND;*out=&Memory;}
 else if(Guid(guid,&gEfiAcpiTableProtocolGuid)){if(Is("no-ACPI"))return EFI_NOT_FOUND;*out=&Acpi;}
 else assert(0);return 0;
}
static EFI_STATUS EFIAPI GetAttributes(EFI_MEMORY_ATTRIBUTE_PROTOCOL *self,EFI_PHYSICAL_ADDRESS addr,UINT64 n,UINT64 *attr){
 assert(self==&Memory&&n==4096&&addr==(((UINTN)Images[1]+(Variant?0xe140:0xe0e8)+56)&~0xfffULL));
 if(Is("attribute-error"))return EFI_UNSUPPORTED;*attr=Is("read-only-slot")?EFI_MEMORY_RO:0;return 0;
}
static EFI_STATUS EFIAPI Install(EFI_ACPI_TABLE_PROTOCOL *self,VOID *table,UINTN n,UINTN *key){
 assert(self==&Acpi&&n==36+1608);if(Is("install-error"))return EFI_DEVICE_ERROR;
 PublishedData=malloc(n);CopyMem(PublishedData,table,n);PublishedSize=n;*key=128;Published++;return 0;
}
int main(int argc,char**argv){
 assert(argc==6);Case=argv[1];Variant=Is("legacy")?0:1;
 Images[0]=Read(argv[2],"Pil-mapped.bin",&ImageSizes[0]);Images[1]=Read(argv[2],"Scm-mapped.bin",&ImageSizes[1]);
 Cfgs[0]=Read(argv[3],"FULL_ADSP_DTB-config.bin",&CfgSizes[0]);Cfgs[1]=Read(argv[3],"FULL_ADSP-config.bin",&CfgSizes[1]);assert(CfgSizes[0]==568&&CfgSizes[1]==568);
 Mdts[0]=Read(argv[4],"adsp_dtb.mdt",&MdtSizes[0]);Mdts[1]=Read(argv[4],"adsp.mdt",&MdtSizes[1]);
 for(UINTN i=0;i<2;i++){
  CONST G128_IMAGE *spec=i?&mScmImage:&mPilImage;
  char name[32];snprintf(name,sizeof(name),"%s-all-relocs.bin",i?"Scm":"Pil");UINTN bytes;UINT8*fix=Read(argv[2],name,&bytes);assert(bytes%4==0);
  for(UINTN j=0;j<bytes;j+=4){UINT32 off;CopyMem(&off,fix+j,4);SetQ(Images[i]+off,Q(Images[i]+off)+(UINTN)Images[i]);}free(fix);
  Loaded[i].ImageBase=Images[i];Loaded[i].ImageSize=spec->ImageBytes;
 }
 if(Is("PIL-code"))Images[0][0x2000]^=1;
 if(Is("SCM-code"))Images[1][0x2000]^=1;
 if(Is("PIL-revision"))SetQ(Images[0]+0x16188,1);
 if(Is("PIL-getter"))SetQ(Images[0]+0x16188+48,(UINTN)Images[0]+0x17e0);
 if(Is("SCM-function"))SetQ(Images[1]+0xe140+56,(UINTN)Images[1]+0x3f98);
 if(Is("image-size"))Loaded[0].ImageSize--;
 Bs.LocateHandleBuffer=Locate;Bs.HandleProtocol=Handle;Bs.LocateProtocol=LocateProto;Bs.FreePool=FreeCached;
 Memory.GetMemoryAttributes=GetAttributes;Acpi.InstallAcpiTable=Install;
 EFI_STATUS s=OpenRunPilMetadataProbe(!Is("preflight-failed"));
 if(Is("no-ACPI"))assert(s==EFI_NOT_FOUND&&!Published);
 else if(Is("install-error"))assert(s==EFI_DEVICE_ERROR&&!Published);
 else if(Is("report-allocation"))assert(s==EFI_OUT_OF_RESOURCES&&!Published);
 else {
  assert(!s&&Published==1&&PublishedSize==1644);UINT8 sum=0;for(UINTN i=0;i<PublishedSize;i++)sum+=PublishedData[i];assert(!sum);
  G128_REPORT aligned,*r=&aligned;CopyMem(r,PublishedData+36,sizeof(*r));assert(r->Size==1608&&r->Version==1&&r->Magic==G128_MAGIC&&!r->RequestedPasStages);
  BOOLEAN metadataGood=Is("success")||Is("legacy")||Is("no-SCM")||Is("SCM-code")||Is("SCM-function")||Is("no-attributes")||Is("attribute-error")||Is("read-only-slot");
  if(metadataGood)assert(r->Status[0]==0&&MetaCalls==2&&HeaderCalls==2&&Releases==2&&CachedFrees==6);
  if(Is("preflight-failed")||Is("PIL-code")||Is("no-PIL")||Is("PIL-revision")||Is("PIL-getter")||Is("image-size")||Is("image-enumeration")||Is("duplicate-image")||Is("too-many-images")||Is("config-warning")||Is("config-data")||Is("hash-allocation"))assert(!MetaCalls&&r->Status[0]!=0);
  if(Is("uncached-release")||Is("uncached-short-release")||Is("pool-free"))assert(MetaCalls==1&&r->Status[13]!=0&&r->Status[0]!=0);
  if(Is("metadata-error")||Is("metadata-partial")||Is("cached-hash")||Is("uncached-hash")||Is("header-error"))assert(MetaCalls==2&&r->Status[0]!=0);
  if(Is("success")){FILE*f=fopen(argv[5],"wb");assert(f&&fwrite(PublishedData,1,PublishedSize,f)==PublishedSize&&!fclose(f));}
 }
 UINTN before=MetaCalls;assert(OpenRunPilMetadataProbe(TRUE)==EFI_ALREADY_STARTED&&MetaCalls==before);
 printf("{\"case\":\"%s\",\"passed\":true,\"metadata_calls\":%zu,\"header_calls\":%zu,\"PAS_requests\":0}\n",Case,MetaCalls,HeaderCalls);
 free(PublishedData);for(UINTN i=0;i<2;i++){free(Images[i]);free(Cfgs[i]);free(Mdts[i]);}return 0;
}
