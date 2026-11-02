/* Actual adapter C and real UEFI headers; every firmware service is a model. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#define OPEN_GUARDED_ADSP_MODEL
#include "OpenGuardedAdsp.c"
#include "cfg-fixtures.h"
EFI_GUID gEfiGraphicsOutputProtocolGuid=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
EFI_GUID gEfiAcpiTableProtocolGuid=EFI_ACPI_TABLE_PROTOCOL_GUID;
static EFI_BOOT_SERVICES Bs;
EFI_BOOT_SERVICES *gBS=&Bs;
static EFI_ACPI_TABLE_PROTOCOL Acpi;
static EFI_GRAPHICS_OUTPUT_PROTOCOL Gop[2];
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE Mode[2];
static UINT8 PilImage[0x42000],ScmImage[0x42000];
static G128_REPORT Meta;
static const char *Case;
static unsigned LoadCalls,RawCalls,Published,Allocs,Frees,ScmLocates,Started;
static UINT8 Wire[4096];static UINTN WireBytes;
static int Is(const char *s){return strcmp(Case,s)==0;}
static void *Pil(void){return PilImage+0x16188;}
static void *Scm(void){return ScmImage+0xe140;}
static UINT64 Original(void){return (UINTN)ScmImage+0x3f94;}
static UINT64 Other(void){return (UINTN)ScmImage+0x4000;}
VOID *EFIAPI CopyMem(VOID *d,CONST VOID *s,UINTN n){
 if(Started&&d==ScmImage+0xe178&&n==8){UINT64 v;memcpy(&v,s,8);
  if(Is("hook-write-fail")&&v==(UINTN)Observe)return d;
  if(Is("restore-write-fail")&&v==Original())return d;
 }
 return memcpy(d,s,n);
}
VOID *EFIAPI ZeroMem(VOID *d,UINTN n){return memset(d,0,n);}
VOID EFIAPI MemoryFence(VOID){}
VOID *EFIAPI AllocateZeroPool(UINTN n){Allocs++;return calloc(1,n);}
VOID EFIAPI FreePool(VOID *p){assert(p);Frees++;free(p);}
UINTN EFIAPI Print(CONST CHAR16 *fmt,...){(void)fmt;return 0;}
static VOID Log(CONST CHAR8 *fmt,...){(void)fmt;}
BOOLEAN OpenKernelWindowInventoryComplete(VOID){return !Is("inventory-refused");}
CONST G128_REPORT *OpenGetPilMetadataReport(VOID){return Is("metadata-null")?NULL:&Meta;}
OP_U64 OpenDspCurrentEl(void){return Is("EL0")?0:Is("EL3")?3:Is("EL2")?2:1;}
OP_U64 OpenDspAt(void *ctx,OP_U64 address,unsigned write){
 assert(*(UINT64 *)ctx==OpenDspCurrentEl());
 if(Is("CPU-read-fault")&&!write)return 1;
 if(Is("CPU-write-fault")&&write)return 1;
 if(Is("CPU-alias"))return (0xffULL<<56)|(address+4096);
 if(Is("CPU-device"))return address;
 if(Is("stale-before-hook")&&address==0xae87f000&&write)SetQ(ScmImage+0xe178,Other());
 return (0xffULL<<56)|address;
}
static EFI_STATUS EFIAPI Locate(EFI_GUID *guid,VOID *registration,VOID **out){
 assert(registration==NULL);
 if(!memcmp(guid,&mPilGuid,16)){if(Is("PIL-missing"))return EFI_NOT_FOUND;*out=Pil();return EFI_SUCCESS;}
 if(!memcmp(guid,&mScmGuid,16)){
  ScmLocates++;if(Is("SCM-missing"))return EFI_NOT_FOUND;
  *out=Is("protocol-restore-changed")&&ScmLocates>1?Pil():Scm();return EFI_SUCCESS;
 }
 assert(!memcmp(guid,&gEfiAcpiTableProtocolGuid,16));*out=&Acpi;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Handles(EFI_LOCATE_SEARCH_TYPE search,EFI_GUID *guid,VOID *key,UINTN *count,EFI_HANDLE **out){
 assert(search==ByProtocol&&!memcmp(guid,&gEfiGraphicsOutputProtocolGuid,16)&&key==NULL);
 if(Is("GOP-missing"))return EFI_NOT_FOUND;
 *count=Is("GOP-many")?9:Is("GOP-second-overlap")?2:1;
 *out=AllocateZeroPool(*count*sizeof(**out));for(UINTN i=0;i<*count;i++)(*out)[i]=&Gop[i%2];return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Handle(EFI_HANDLE h,EFI_GUID *guid,VOID **out){
 assert(!memcmp(guid,&gEfiGraphicsOutputProtocolGuid,16));*out=h;return EFI_SUCCESS;
}
static EFI_TPL EFIAPI Raise(EFI_TPL tpl){assert(tpl==TPL_HIGH_LEVEL);return TPL_APPLICATION;}
static VOID EFIAPI Restore(EFI_TPL tpl){assert(tpl==TPL_APPLICATION);}
static EFI_STATUS EFIAPI Install(EFI_ACPI_TABLE_PROTOCOL *self,VOID *table,UINTN n,UINTN *key){
 assert(self==&Acpi&&n==sizeof(EFI_ACPI_DESCRIPTION_HEADER)+sizeof(G134_REPORT));
 EFI_ACPI_DESCRIPTION_HEADER *h=table;assert(h->Signature==SIGNATURE_32('O','A','D','P')&&h->Length==n);
 UINT8 sum=0;for(UINTN i=0;i<n;i++)sum=(UINT8)(sum+((UINT8 *)table)[i]);assert(!sum);
 assert(!memcmp(h+1,&mResult,sizeof(mResult)));assert(n<=sizeof(Wire));memcpy(Wire,table,n);WireBytes=n;
 *key=134;Published++;return EFI_SUCCESS;
}
UINT64 RawSip(VOID *self,UINT32 command,UINT32 param,OP_U64 *args,OP_U64 *out){
 assert(self==Scm()&&command!=0x42000206&&param&&args[9]==0x99);
 unsigned step=RawCalls++;for(unsigned i=0;i<4;i++)out[i]=i?0:1;
 out[2]=0x2200+step;out[3]=0x3300+step;
 if(!strncmp(Case,"service-",8)&&step==(unsigned)atoi(Case+8))out[1]=~6ULL;
 if(Is("transport-main-auth")&&step==5)return EFI_DEVICE_ERROR;
 return EFI_SUCCESS;
}
UINT64 LoadCfg(UINTN method,VOID *config){
 assert(method==(UINTN)PilImage+0x172c&&LoadCalls<2);
 unsigned index=LoadCalls++;UINT8 expected[568];memcpy(expected,FixtureConfig[index],568);
 UINT64 base=index?0xaa000000:0xa9f80000;memcpy(expected+0xf0,&base,8);
 if(index)memset(expected+0x174,0,64);else expected[0x102]=1;
 assert(!memcmp(expected,config,sizeof expected));
 if(Is("loader-no-PAS"))return EFI_SUCCESS;
 for(unsigned stage=0;stage<3;stage++){
  OP_U64 args[10]={index?1:36,stage==0?0x38000000:stage==1?base:0,stage==1?(index?0x4880000:0x80000):0},out[4]={0};args[9]=0x99;
  UINT32 command=0x42000200+(stage==2?5:stage+1),param=stage==0?0x82:stage==1?3:1;
  typedef UINT64(EFIAPI *CALL)(VOID *,UINT32,UINT32,OP_U64 *,OP_U64 *);
  UINT64 status=((CALL)(UINTN)Q(ScmImage+0xe178))(Scm(),command,param,args,out);
  if(status)return EFI_LOAD_ERROR;
 }
 if(Is("slot-restore-changed"))SetQ(ScmImage+0xe178,Other());
 if((Is("DTB-post-fail")&&!index)||(Is("main-post-fail")&&index))return EFI_LOAD_ERROR;
 return EFI_SUCCESS;
}
int main(int argc,char **argv){
 assert(argc==2||argc==3);Case=argv[1];Bs.LocateProtocol=Locate;Bs.LocateHandleBuffer=Handles;Bs.HandleProtocol=Handle;Bs.RaiseTPL=Raise;Bs.RestoreTPL=Restore;Acpi.InstallAcpiTable=Install;
 for(unsigned i=0;i<2;i++){Gop[i].Mode=&Mode[i];Mode[i].FrameBufferBase=0xb8000000;Mode[i].FrameBufferSize=0x2b00000;}
 if(Is("GOP-overlap"))Mode[0].FrameBufferBase=0xa9f80000;
 if(Is("GOP-second-overlap"))Mode[1].FrameBufferBase=0xa9f80000;
 if(Is("GOP-overflow")){Mode[0].FrameBufferBase=~7ULL;Mode[0].FrameBufferSize=16;}
 Meta.Size=sizeof(Meta);Meta.Version=1;Meta.Magic=G128_MAGIC;Meta.Flags=0x7ff;Meta.ScmABI=2;Meta.ImagesAttempted=2;
 Meta.ImageBase[0]=(UINTN)PilImage;Meta.ImageBase[1]=(UINTN)ScmImage;Meta.ScmTableRva=0xe140;Meta.ScmFunctionRva=0x3f94;memcpy(Meta.Config,FixtureConfig,sizeof(Meta.Config));
 SetQ(PilImage+0x16188,0x10004);SetQ(PilImage+0x16198,(UINTN)PilImage+0x172c);SetQ(ScmImage+0xe140,0x40001);SetQ(ScmImage+0xe178,Original());
 if(Is("metadata-size"))Meta.Size--;if(Is("metadata-magic"))Meta.Magic=0;if(Is("metadata-status"))Meta.Status[0]=EFI_DEVICE_ERROR;
 if(Is("metadata-flags"))Meta.Flags^=2;if(Is("metadata-legacy"))Meta.ScmABI=1;if(Is("metadata-attempts"))Meta.ImagesAttempted=1;if(Is("metadata-PAS-count"))Meta.RequestedPasStages=1;
 if(Is("PIL-revision"))SetQ(Pil(),0);if(Is("PIL-method"))SetQ(PilImage+0x16198,(UINTN)PilImage+0x1708);
 if(Is("SCM-revision"))SetQ(Scm(),0);if(Is("SCM-method"))SetQ(ScmImage+0xe178,Other());
 if(Is("config-base"))Meta.Config[0][0xf0]^=1;
 if(Is("config-backup"))Meta.Config[1][0x114]=1;
 if(Is("config-postimage"))Meta.Config[1][0x1b4]=1;
 BOOLEAN mayContinue=FALSE;Started=1;EFI_STATUS s=OpenRunGuardedAdsp(!Is("source-refused"),Log,&mayContinue);
 assert(Published==1&&Allocs==Frees&&mResult.FinalStatus==s);
 if(Is("success")||Is("EL2")){
  assert(s==EFI_SUCCESS&&mayContinue&&LoadCalls==2&&RawCalls==6&&mResult.Flags==2047&&mResult.Count==6&&mResult.HookStores==2&&mResult.AuthAcceptedMask==3);
  assert(mResult.CpuPages==18689&&mResult.CpuQueries==37378);
 }else if(!strncmp(Case,"service-",8)){
  unsigned step=atoi(Case+8);assert(s==EFI_DEVICE_ERROR&&mayContinue&&RawCalls==step+1&&mResult.Count==step+1&&LoadCalls==(step<3?1:2)&&mResult.HookStores==2&&mResult.Fault==OP_SERVICE_RESULT);
 }else if(Is("transport-main-auth")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&RawCalls==6&&mResult.AuthEnteredMask==3&&mResult.AuthAcceptedMask==1&&mResult.Fault==OP_TRANSPORT);
 }else if(Is("DTB-post-fail")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&LoadCalls==1&&RawCalls==3&&mResult.AuthAcceptedMask==1);
 }else if(Is("main-post-fail")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&LoadCalls==2&&RawCalls==6&&mResult.AuthAcceptedMask==3&&!(mResult.Flags&1024));
 }else if(Is("loader-no-PAS")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&LoadCalls==1&&!RawCalls);
 }else if(Is("slot-restore-changed")||Is("protocol-restore-changed")||Is("restore-write-fail")){
  assert(s==EFI_DEVICE_ERROR&&!mayContinue&&mResult.FatalRestore&&mResult.Status[7]==EFI_DEVICE_ERROR);
 }else if(Is("stale-before-hook")){
  assert(s==EFI_DEVICE_ERROR&&!mayContinue&&!LoadCalls&&!RawCalls&&!mResult.HookStores);
 }else if(Is("hook-write-fail")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&!LoadCalls&&!RawCalls&&mResult.HookStores==1);
 }else{
  assert(s!=EFI_SUCCESS&&mayContinue&&!LoadCalls&&!RawCalls&&!mResult.HookStores);
 }
 if(mayContinue&&mResult.HookStores)assert(Q(ScmImage+0xe178)==Original());
 unsigned before=LoadCalls;BOOLEAN priorContinue=mayContinue;
 assert(OpenRunGuardedAdsp(TRUE,Log,&mayContinue)==EFI_ALREADY_STARTED&&LoadCalls==before&&Published==1&&mayContinue==priorContinue);
 if(argc==3){FILE *f=fopen(argv[2],"wb");assert(f&&WireBytes&&fwrite(Wire,1,WireBytes,f)==WireBytes);assert(!fclose(f));}
 printf("{\"passed\":true,\"case\":\"%s\",\"PIL_calls\":%u,\"SCM_calls_modeled\":%u,\"hook_stores_modeled\":%u,\"report_bytes\":%zu,\"native_operations\":0}\n",Case,LoadCalls,RawCalls,mResult.HookStores,sizeof(mResult));
}
