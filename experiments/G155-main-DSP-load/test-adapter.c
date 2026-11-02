/* Actual adapter and real UEFI headers; all firmware services are models. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#define OPEN_GUARDED_ADSP_MODEL
#include <PiDxe.h>
#include "OpenGuardedAdsp.c"
#include "cfg-fixtures.h"
#include "model-fixtures.h"
#include <sys/mman.h>
EFI_GUID gEfiGraphicsOutputProtocolGuid=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
EFI_GUID gEfiAcpiTableProtocolGuid=EFI_ACPI_TABLE_PROTOCOL_GUID;
static EFI_BOOT_SERVICES Bs;
EFI_BOOT_SERVICES *gBS=&Bs;
static EFI_ACPI_TABLE_PROTOCOL Acpi;
static EFI_GRAPHICS_OUTPUT_PROTOCOL Gop[2];
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE Mode[2];
static UINT8 PilImage[0x42000] __attribute__((aligned(4096)));
static UINT8 ScmImage[0x42000] __attribute__((aligned(4096)));
static G128_REPORT Meta;
static const char *Case;
static unsigned LoadCalls,RawCalls,Published,Allocs,Frees,ScmLocates,Started,Raises;
static OPEN_DTB_ADMISSION_REPORT Dtb;
static unsigned DtbInitializations,CopyChecks,PayloadChecks;
static UINT8 *Ram;static const char *PayloadDir;
static int MainCheck=-1;static unsigned MainReadCalls,MainMmio;
static EFI_DXE_SERVICES Ds;EFI_DXE_SERVICES *gDS=&Ds;
static UINT8 DspWire[16384],SerialWire[4096];static UINTN DspBytes,SerialBytes;
static int Is(const char*s){return strcmp(Case,s)==0;}
/* The separate 97-case component test runs the actual admission C. Here its
 * boundary is modeled so failures can be injected around original PIL/SCM. */
EFI_STATUS OpenDtbAdmissionInit(VOID){
 assert(!DtbInitializations++);Dtb.Size=sizeof(Dtb);Dtb.Version=1;
 Dtb.CopyStatus=Dtb.PayloadStatus=EFI_NOT_READY;
 for(unsigned i=0;i<3;i++)Dtb.Check[i].Status=EFI_NOT_READY;
 return Is("admission-init-refused")?EFI_ACCESS_DENIED:EFI_SUCCESS;
}
CONST OPEN_DTB_ADMISSION_REPORT *OpenGetDtbAdmissionReport(VOID){return&Dtb;}
static void CompleteCheck(unsigned index){
 OPEN_DTB_CHECK*r=&Dtb.Check[index];r->Status=0;r->CpuEl=OpenDspCurrentEl();
 r->CpuPages=3;r->AtQueries=11;r->ReadPar=r->WritePar=0x440000009e982000ULL;
 UINT32 clocks[]={0,1,1,0xf822f800,0x04070000};memcpy(r->Clock,clocks,sizeof(clocks));
 r->HwVersion=0x90000001;r->MmioReads=43;r->MmioPages=5;r->Complete=1;
}
EFI_STATUS OpenDtbAuthorizeCopy(BOOLEAN ready,OPEN_DTB_LOG log){
 assert(ready&&log&&!CopyChecks++&&RawCalls==2&&mObserver.Phase[0]==2&&mObserver.Busy);
 Dtb.CopyAttempts=1;
 if(Is("copy-admission-refused")){Dtb.Check[0].Reason=DTB_DEMURA;return Dtb.CopyStatus=Dtb.Check[0].Status=EFI_ACCESS_DENIED;}
 CompleteCheck(0);Dtb.CopyGranted=1;return Dtb.CopyStatus=EFI_SUCCESS;
}
EFI_STATUS OpenDtbVerifyPayload(BOOLEAN ready,OPEN_DTB_LOG log){
 assert(ready&&log&&!PayloadChecks++&&CopyChecks==1&&RawCalls==2&&mObserver.Busy);
 Dtb.PayloadAttempts=1;CompleteCheck(1);
 if(Is("payload-admission-refused")){Dtb.HashOutcome=2;Dtb.PayloadHashed=1;return Dtb.PayloadStatus=EFI_SECURITY_VIOLATION;}
 static const UINT8 hash[32]={0xf7,0x18,0x92,0xad,0x4f,0xf2,0xac,0x11,0x00,0xa0,0x7f,0x63,0xb4,0xa5,0xef,0x24,0x67,0x49,0xa9,0x59,0x37,0xa7,0x97,0xd5,0x04,0x80,0xe7,0xc7,0x0b,0x1b,0x2f,0x94};
 Dtb.PayloadHashed=Dtb.PayloadMatched=1;Dtb.HashOutcome=3;memcpy(Dtb.Digest,hash,32);CompleteCheck(2);
 return Dtb.PayloadStatus=EFI_SUCCESS;
}
static void*Pil(void){return PilImage+0x16188;}
static void*Scm(void){return ScmImage+0xe140;}
static UINT64 Original(void){return(UINTN)ScmImage+0x3f94;}
static UINT64 Other(void){return(UINTN)ScmImage+0x4000;}
VOID*EFIAPI CopyMem(VOID*d,CONST VOID*s,UINTN n){
 if(Started&&n==8){UINT64 v;memcpy(&v,s,8);
  if(d==ScmImage+0xe178){if(Is("hook-write-fail")&&v==(UINTN)Observe)return d;if(Is("restore-write-fail")&&v==Original())return d;}
  if(d==ScmImage+0xe580){if(Is("serial-hook-write-fail")&&v==(UINTN)&mSerialProxy)return d;if(Is("serial-restore-write-fail")&&v==mSerial.Report.SavedCache)return d;}
 }
 return memcpy(d,s,n);
}
VOID*EFIAPI ZeroMem(VOID*d,UINTN n){return memset(d,0,n);}
VOID*EFIAPI SetMem(VOID*d,UINTN n,UINT8 v){return memset(d,v,n);}
INTN EFIAPI CompareMem(CONST VOID*a,CONST VOID*b,UINTN n){return memcmp(a,b,n);}
VOID*EFIAPI AllocatePool(UINTN n){Allocs++;return calloc(1,n);}
VOID EFIAPI MemoryFence(VOID){}
VOID*EFIAPI AllocateZeroPool(UINTN n){Allocs++;return calloc(1,n);}
VOID EFIAPI FreePool(VOID*p){assert(p);Frees++;free(p);}
UINTN EFIAPI Print(CONST CHAR16*fmt,...){(void)fmt;return 0;}
static VOID Log(CONST CHAR8*fmt,...){(void)fmt;}
BOOLEAN OpenKernelWindowInventoryComplete(VOID){return!Is("inventory-refused");}
BOOLEAN OpenPilSetupFootprintReady(VOID){return!Is("PIL-footprint-refused");}
CONST G128_REPORT*OpenGetPilMetadataReport(VOID){return Is("metadata-null")?NULL:&Meta;}
OP_U64 OpenDspCurrentEl(void){return Is("EL0")?0:Is("EL3")?3:Is("EL2")?2:1;}
OP_U64 OpenDspAt(void*ctx,OP_U64 at,unsigned write){
 assert(*(UINT64*)ctx==OpenDspCurrentEl());
 if(at==0xaf08000||at==0xaf09000||at==0xae00000||at==0xae6a000||at==0xae6b000){assert(!write);return at;}
 if(MainCheck>=0&&at>=0x9ea00000&&at<0xa3280000){
  if((Is("main-pre-AT")&&MainCheck==1||Is("main-post-AT")&&MainCheck==2)&&at==0xa2836000)return 1;
 }
 if(Is("CPU-read-fault")&&!write)return 1;if(Is("CPU-write-fault")&&write)return 1;
 if(Is("CPU-alias"))return(0xffULL<<56)|(at+4096);if(Is("CPU-device"))return at;
 if(Is("stale-before-hook")&&at==0xa327f000&&write)SetQ(ScmImage+0xe178,Other());
 if(Is("CPU-PIL-WB")&&at>=0x9e980000ULL&&at<0xa3280000ULL)return(0xffULL<<56)|at;
 if(Is("CPU-SCM-NC")&&!(at>=0x9e980000ULL&&at<0xa3280000ULL))return(0x44ULL<<56)|at;
 return((at>=0x9e980000ULL&&at<0xa3280000ULL?0x44ULL:0xffULL)<<56)|at;
}
static EFI_STATUS EFIAPI Locate(EFI_GUID*g,VOID*registration,VOID**out){
 assert(!registration);
 if(!memcmp(g,&mPilGuid,16)){if(Is("PIL-missing"))return EFI_NOT_FOUND;*out=Pil();return EFI_SUCCESS;}
 if(!memcmp(g,&mScmGuid,16)){
  ScmLocates++;if(Is("SCM-missing"))return EFI_NOT_FOUND;
  *out=Is("protocol-restore-changed")&&ScmLocates>1?Pil():Scm();return EFI_SUCCESS;
 }
 assert(!memcmp(g,&gEfiAcpiTableProtocolGuid,16));*out=&Acpi;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Handles(EFI_LOCATE_SEARCH_TYPE search,EFI_GUID*g,VOID*key,UINTN*count,EFI_HANDLE**out){
 assert(search==ByProtocol&&!memcmp(g,&gEfiGraphicsOutputProtocolGuid,16)&&!key);
 if(Is("GOP-missing"))return EFI_NOT_FOUND;*count=Is("GOP-many")?9:Is("GOP-second-overlap")?2:1;
 *out=AllocateZeroPool(*count*sizeof(**out));for(UINTN i=0;i<*count;i++)(*out)[i]=&Gop[i%2];return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Handle(EFI_HANDLE h,EFI_GUID*g,VOID**out){assert(!memcmp(g,&gEfiGraphicsOutputProtocolGuid,16));*out=h;return EFI_SUCCESS;}
static EFI_TPL EFIAPI Raise(EFI_TPL tpl){assert(tpl==TPL_HIGH_LEVEL);if(++Raises==1&&Is("serial-stale-before-hook"))SetQ(ScmImage+0xe580,Other());return TPL_APPLICATION;}
static VOID EFIAPI Restore(EFI_TPL tpl){assert(tpl==TPL_APPLICATION);}
static EFI_STATUS EFIAPI Install(EFI_ACPI_TABLE_PROTOCOL*self,VOID*table,UINTN n,UINTN*key){
 assert(self==&Acpi);EFI_ACPI_DESCRIPTION_HEADER*h=table;UINT8 sum=0;for(UINTN i=0;i<n;i++)sum=(UINT8)(sum+((UINT8*)table)[i]);assert(!sum&&h->Length==n&&h->OemRevision==155);Published++;
 if(h->Signature==SIGNATURE_32('O','A','D','P')){
  assert(n==sizeof(*h)+sizeof(mResult)&&!memcmp(h+1,&mResult,sizeof(mResult)));memcpy(DspWire,table,n);DspBytes=n;if(Is("DSP-publication-fail"))return EFI_DEVICE_ERROR;
 }else{
  assert(h->Signature==SIGNATURE_32('O','S','E','R')&&n==sizeof(*h)+sizeof(mSerial.Report)&&!memcmp(h+1,&mSerial.Report,sizeof(mSerial.Report)));memcpy(SerialWire,table,n);SerialBytes=n;if(Is("serial-publication-fail"))return EFI_DEVICE_ERROR;
 }
 *key=151;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Gcd(EFI_PHYSICAL_ADDRESS at,EFI_GCD_MEMORY_SPACE_DESCRIPTOR*d){
 memset(d,0,sizeof(*d));
 if(at==0x9ea00000){
  MainCheck++;assert(MainCheck<3);MainMmio=0;
  d->BaseAddress=0x8a800000;d->Length=0x18a80000;d->GcdMemoryType=EfiGcdMemoryTypeReserved;d->Capabilities=EFI_MEMORY_UC;
  if(Is("main-copy-owner")&&MainCheck==0)d->ImageHandle=(VOID*)1;
  return EFI_SUCCESS;
 }
 const UINT64 pages[]={0xaf08000,0xaf09000,0xae00000,0xae6a000,0xae6b000};
 unsigned i;for(i=0;i<5;i++)if(at==pages[i])break;assert(i<5);
 d->BaseAddress=at;d->Length=4096;d->GcdMemoryType=EfiGcdMemoryTypeMemoryMappedIo;d->Capabilities=EFI_MEMORY_UC;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Map(UINTN*bytes,EFI_MEMORY_DESCRIPTOR*map,UINTN*key,UINTN*stride,UINT32*version){
 *stride=48;*version=1;*key=1;if(!map){*bytes=48;return EFI_BUFFER_TOO_SMALL;}
 assert(*bytes>=48);memset(map,0,48);*bytes=48;
 map->PhysicalStart=0x8a800000;map->NumberOfPages=0x18a80;map->Type=EfiReservedMemoryType;map->Attribute=EFI_MEMORY_UC;return EFI_SUCCESS;
}
UINT32 OpenMainModelRead(UINT64 at){
 MainMmio++;
 const UINT64 clocks[]={0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004};
 const UINT32 native[]={0,1,1,0xf822f800,0x04070000};
 for(unsigned i=0;i<5;i++)if(at==clocks[i])return native[i];
 if(at==0xae00000)return 0x90000001;assert(at==0xae6a604||at==0xae6b604);
 if((Is("main-pre-demura")&&MainCheck==1||Is("main-post-demura")&&MainCheck==2)&&at==0xae6b604)return 1;
 return 0;
}
static void PopulateMain(void){
 assert(!Ram&&mObserver.CopyAllowed[1]==1&&mObserver.Phase[1]==2);
 Ram=mmap(NULL,0x4880000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(Ram!=MAP_FAILED);memset(Ram,0xa5,0x4880000);
 for(unsigned i=0;i<OMP_EXTENTS;i++){
  assert(mMainPlan[i].Base==ModelBase[i]&&mMainPlan[i].Bytes==ModelBytes[i]&&mMainPlan[i].Kind==ModelKind[i]);
  UINT8*dest=Ram+ModelBase[i]-0x9ea00000;
  if(ModelKind[i]==2){memset(dest,0,ModelBytes[i]);continue;}
  char path[2048];int n=snprintf(path,sizeof(path),"%s/%s",PayloadDir,FileName[i]);assert(n>0&&(unsigned)n<sizeof(path));FILE*f=fopen(path,"rb");assert(f&&fread(dest,1,ModelBytes[i],f)==ModelBytes[i]&&fgetc(f)==EOF&&!fclose(f));
 }
 if(Is("main-hash-last"))Ram[ModelBase[88]+ModelBytes[88]-1-0x9ea00000]^=1;
 if(Is("main-zero-last")){for(unsigned i=89;i--;)if(ModelKind[i]==2){Ram[ModelBase[i]+ModelBytes[i]-1-0x9ea00000]^=1;break;}}
 if(Is("main-changed-holes"))for(unsigned i=0;i<5;i++)Ram[Untouched[i][0]-0x9ea00000]^=1;
 assert(!mprotect(Ram,0x4880000,PROT_READ));
}
EFI_STATUS MainModelRead(UINT64 at,UINTN n,VOID*out){
 assert(Ram&&MainReadRange(at,n)&&MainCheck==1&&mObserver.Busy&&mObserver.AuthEnteredMask==1);MainReadCalls++;
 if(Is("main-read-error")&&MainReadCalls==1)return EFI_DEVICE_ERROR;
 memcpy(out,Ram+at-0x9ea00000,n);
 if(Is("main-owner-after-read")&&MainReadCalls==1)SetQ(ScmImage+0xe580,Other());
 return EFI_SUCCESS;
}
UINT64 RawSip(VOID*self,UINT32 command,UINT32 param,OP_U64*args,OP_U64*out){
 assert(self==Scm()&&command!=0x42000206&&args&&args[9]==0x99);
 unsigned call=RawCalls++,image=call/3,step=call%3;assert(call<6&&args[0]==(image?1u:36u));
 assert(command==(step==2?0x42000205:0x42000201+step)&&param==(step==0?0x82:step==1?3:1));
 if(image&&step==2)assert(mPayload.Report.Complete&&mPayload.Report.VerifiedBytes==64910785&&MainCheck==2);
 assert(Q(ScmImage+0xe580)==(UINTN)&mSerialProxy);out[0]=1;out[1]=0;out[2]=0x2020;out[3]=0x3030;
 if(Is("serial-change-after-init")&&!call)SetQ(ScmImage+0xe580,Other());
 const char*prefix=image?"main-":"";char kind[64];
 snprintf(kind,sizeof(kind),"%sservice-%s",prefix,step==0?"init":step==1?"mem":"auth");if(Is(kind)){out[1]=~6ULL;return EFI_SUCCESS;}
 snprintf(kind,sizeof(kind),"%sheader-%s",prefix,step==0?"init":step==1?"mem":"auth");if(Is(kind)){out[0]=0;return EFI_SUCCESS;}
 snprintf(kind,sizeof(kind),"%serror-%s",prefix,step==0?"init":step==1?"mem":"auth");
 int fail=Is(kind)||(!image&&step==1&&(Is("error-native-code")||Is("error-unsupported")||Is("error-already")||Is("serial-restore-write-fail")||Is("restore-write-fail")||Is("serial-change-after-mem")||Is("slot-change-after-mem")||Is("bad-log")||Is("nonstack-log")||Is("oversized-log")||Is("other-serial")));
 if(!fail)return EFI_SUCCESS;
 UINT32 raw=Is("error-native-code")?0xffcfffbau:Is("error-unsupported")?0xffffffffu:0xfffffffeu;char text[512];
 int length=snprintf(text,sizeof(text),"tz_armv8_smc_call failed, TzStatus = 0x%X,  SmcId = 0x%X  \r\n",raw,command);assert(length>0&&(UINTN)length<sizeof(text));
 if(Is("bad-log"))text[40]='?';G151_SERIAL_PROXY*proxy=(VOID*)(UINTN)Q(ScmImage+0xe580);
 if(Is("other-serial"))assert(!proxy->Poll()&&!proxy->Read((VOID*)(UINTN)0xc7b7000,16));
 if(Is("nonstack-log")){static const char nonstack[]="tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x42000202  \r\n";proxy->Write(nonstack,sizeof(nonstack)-1);}
 else proxy->Write(text,Is("oversized-log")?513:(UINTN)length);
 out[0]=Is("error-already")?~12ULL:0;out[1]=out[2]=out[3]=0;
 if(Is("serial-change-after-mem"))SetQ(ScmImage+0xe580,Other());if(Is("slot-change-after-mem"))SetQ(ScmImage+0xe178,Other());
 return Is("error-unsupported")?EFI_UNSUPPORTED:Is("error-already")?EFI_ALREADY_STARTED:EFI_DEVICE_ERROR;
}
UINT64 LoadCfg(UINTN method,VOID*config){
 unsigned image=LoadCalls++;assert(method==(UINTN)PilImage+0x172c&&image<2);UINT8 expected[568];memcpy(expected,FixtureConfig[image],568);
 if(image){memset(expected+0x174,0,64);assert(mObserver.DtbPublicComplete&&mResult.DtbMarkerStatus==0&&mResult.DtbPublicSuccess);}
 else expected[0x102]=1;
 assert(!memcmp(config,expected,sizeof expected));UINT64 base=image?0x9ea00000:0x9e980000,bytes=image?0x4880000:0x80000;
 if((!image&&Is("loader-no-PAS"))||(image&&Is("main-loader-no-PAS")))return EFI_SUCCESS;
 for(unsigned step=0;step<3;step++){
  if(step==2&&((!image&&(Is("loader-segment-failure")||Is("loader-PRE-failure")))||(image&&(Is("main-loader-segment-failure")||Is("main-loader-PRE-failure")))))return EFI_LOAD_ERROR;
  OP_U64 args[10]={image?1u:36u,step==0?0x38000000:step==1?base:0,step==1?bytes:0,0,0,0,0,0,0,0x99},out[4]={0};
  typedef UINT64(EFIAPI*CALL)(VOID*,UINT32,UINT32,OP_U64*,OP_U64*);
  UINT64 status=((CALL)(UINTN)Q(ScmImage+0xe178))(Scm(),step==2?0x42000205:0x42000201+step,step==0?0x82:step==1?3:1,args,out);if(status)return EFI_LOAD_ERROR;
  if(image&&step==1)PopulateMain();
 }
 /* Accepted AUTH must reach the modeled original POST branch unchanged. */
 if((!image&&Is("loader-POST-failure"))||(image&&Is("main-loader-POST-failure")))return EFI_DEVICE_ERROR;
 if(!image&&Is("owner-before-marker"))SetQ(ScmImage+0xe580,Other());
 return EFI_SUCCESS;
}
int main(int argc,char**argv){
 assert(argc==4);Case=argv[1];PayloadDir=argv[3];Bs.GetMemoryMap=Map;Ds.GetMemorySpaceDescriptor=Gcd;Bs.LocateProtocol=Locate;Bs.LocateHandleBuffer=Handles;Bs.HandleProtocol=Handle;Bs.RaiseTPL=Raise;Bs.RestoreTPL=Restore;Acpi.InstallAcpiTable=Install;
 for(unsigned i=0;i<2;i++){Gop[i].Mode=&Mode[i];Mode[i].FrameBufferBase=0xb8000000;Mode[i].FrameBufferSize=0x2b00000;}
 if(Is("GOP-overlap"))Mode[0].FrameBufferBase=0x9e980000;if(Is("GOP-second-overlap"))Mode[1].FrameBufferBase=0x9e980000;if(Is("GOP-overflow")){Mode[0].FrameBufferBase=~7ULL;Mode[0].FrameBufferSize=16;}
 Meta.Size=sizeof(Meta);Meta.Version=1;Meta.Magic=G128_MAGIC;Meta.Flags=0x7ff;Meta.ScmABI=2;Meta.ImagesAttempted=2;Meta.ImageBase[0]=(UINTN)PilImage;Meta.ImageBase[1]=(UINTN)ScmImage;Meta.ScmTableRva=0xe140;Meta.ScmFunctionRva=0x3f94;memcpy(Meta.Config,FixtureConfig,sizeof(Meta.Config));
 SetQ(PilImage+0x16188,0x10004);SetQ(PilImage+0x16198,(UINTN)PilImage+0x172c);SetQ(ScmImage+0xe140,0x40001);SetQ(ScmImage+0xe178,Original());
 UINT64 saved=Is("cached-serial")?0x12345678:Is("already-proxy")?(UINTN)&mSerialProxy:0;SetQ(ScmImage+0xe580,saved);
 if(Is("metadata-size"))Meta.Size--;if(Is("metadata-magic"))Meta.Magic=0;if(Is("metadata-status"))Meta.Status[0]=EFI_DEVICE_ERROR;if(Is("metadata-flags"))Meta.Flags^=2;if(Is("metadata-legacy"))Meta.ScmABI=1;if(Is("metadata-attempts"))Meta.ImagesAttempted=1;if(Is("metadata-PAS-count"))Meta.RequestedPasStages=1;
 if(Is("PIL-revision"))SetQ(Pil(),0);if(Is("PIL-method"))SetQ(PilImage+0x16198,(UINTN)PilImage+0x1708);if(Is("SCM-revision"))SetQ(Scm(),0);if(Is("SCM-method"))SetQ(ScmImage+0xe178,Other());
 if(Is("config-base"))Meta.Config[0][0xf0]^=1;if(Is("config-backup"))Meta.Config[1][0x114]=1;if(Is("config-postimage"))Meta.Config[1][0x1b4]=1;
 assert(!MainReadRange(0xc7b7000,4)&&!MainReadRange(0xc7b7008,4)&&!MainReadRange(0xb000000,4));
 assert(!MainReadRange(0xa104f210,1)&&!MainReadRange(0xa2837000,1)&&!MainReadRange(MAX_UINT64,2)&&!MainReadRange(0x9ea00000,4097));
 BOOLEAN mayContinue=FALSE;Started=1;EFI_STATUS s=OpenRunGuardedAdsp(!Is("source-refused"),Log,&mayContinue);
 assert(Published==2&&Allocs==Frees&&mResult.FinalStatus==s&&LoadCalls<=2&&RawCalls<=6&&!mSerial.Report.Active&&!mSerial.Report.PendingCommand);
 assert(mResult.MainEnabled==1&&mResult.MainLoadReturned==(LoadCalls==2)&&mResult.DtbLoadReturned==(LoadCalls>=1));
 assert(!memcmp(&mResult.Dtb,&Dtb,sizeof(Dtb))&&CopyChecks<=1&&PayloadChecks<=1&&mSerial.Report.OriginalCalls==RawCalls&&mSerial.Report.Count<=1);
 assert(mResult.MainPublicSuccess==(LoadCalls==2&&mResult.Status[6]==0&&mObserver.Phase[1]==3&&mObserver.AuthAcceptedMask==3&&!mResult.Fault));
 if(mResult.MainPublicSuccess){
  assert(s==EFI_ABORTED&&mayContinue&&RawCalls==6&&mResult.DtbPublicComplete&&mSerial.Report.DiagnosticStop&&mResult.Flags==255&&mResult.Payload.Complete&&mResult.Main.AcceptedRefreshes==2);
  assert(MainReadCalls==ExpectedReads&&mResult.Payload.VerifiedBytes==64910785);
 }else{
  assert(s!=EFI_SUCCESS&&s!=EFI_ABORTED&&!mSerial.Report.DiagnosticStop);
  if(Is("main-loader-POST-failure"))assert(LoadCalls==2&&RawCalls==6&&mResult.AuthAcceptedMask==3&&mResult.Payload.Complete&&mResult.Status[6]==EFI_DEVICE_ERROR);
  if(Is("loader-POST-failure"))assert(LoadCalls==1&&RawCalls==3&&mResult.AuthAcceptedMask==1&&!mResult.DtbPublicSuccess&&!mResult.DtbPublicComplete&&(mResult.Fault&OP_DTB_PUBLIC));
  if(Is("main-copy-owner"))assert(RawCalls==5&&!MainReadCalls&&mResult.Fault==OP_COPY_ADMISSION&&mResult.Main.Fault==OMA_CHECK);
  if(Is("main-hash-last")||Is("main-zero-last"))assert(RawCalls==5&&MainReadCalls&&!mResult.Payload.Complete&&mResult.Fault==OP_PAYLOAD_MISMATCH&&mResult.Main.AcceptedRefreshes==1);
  if(!strncmp(Case,"main-post-",10))assert(RawCalls==5&&mResult.Payload.VerifiedBytes==64910785&&!mResult.Payload.Complete&&mResult.Main.AcceptedRefreshes==1&&mResult.Payload.Fault==OMP_POST_ADMISSION);
  if(!strncmp(Case,"main-pre-",9))assert(RawCalls==5&&!MainReadCalls&&!mResult.Payload.Complete&&mResult.Main.AcceptedRefreshes==0&&mResult.Payload.Fault==OMP_ADMISSION);
  if(!strncmp(Case,"main-error-",11))assert(mSerial.Report.Count==1&&mSerial.Report.Records[0].ImageId==1&&mSerial.Report.Records[0].Sequence>=3);
 }
 if(!mResult.DtbPublicComplete)assert(LoadCalls<=1&&MainCheck==-1&&!MainReadCalls);
 if(mSerial.Report.Count){OL_RECORD*r=&mSerial.Report.Records[0];assert(r->Sequence<mResult.Count&&r->ImageId==mResult.Records[r->Sequence].ImageId&&r->ApiStatus==mResult.Records[r->Sequence].OriginalStatus);}
 if(Is("main-owner-after-read")||Is("owner-before-marker"))assert(!mayContinue&&mResult.FatalRestore&&mSerial.Report.FatalRestore);
 assert(mayContinue==!mResult.FatalRestore);
 if(mayContinue&&mSerial.Report.HookStores)assert(Q(ScmImage+0xe580)==saved&&mSerial.Report.RestoreStatus==EFI_SUCCESS);
 if(mayContinue&&mResult.HookStores)assert(Q(ScmImage+0xe178)==Original());
 BOOLEAN before=mayContinue;unsigned calls=RawCalls;assert(OpenRunGuardedAdsp(TRUE,Log,&mayContinue)==EFI_ALREADY_STARTED&&mayContinue==before&&RawCalls==calls&&Published==2);
 if(argc>=3){char path[2048];snprintf(path,sizeof path,"%s-DSP.bin",argv[2]);FILE*f=fopen(path,"wb");assert(f&&fwrite(DspWire,1,DspBytes,f)==DspBytes&&!fclose(f));snprintf(path,sizeof path,"%s-OSER.bin",argv[2]);f=fopen(path,"wb");assert(f&&fwrite(SerialWire,1,SerialBytes,f)==SerialBytes&&!fclose(f));}
 if(Ram)assert(!munmap(Ram,0x4880000));
 printf("{\"passed\":true,\"case\":\"%s\",\"PIL_calls\":%u,\"original_SCM_calls_modeled\":%u,\"SCM_slot_stores\":%u,\"serial_cache_stores\":%u,\"captured_errors\":%u,\"AUTH_entered_mask\":%u,\"DTB_public_success\":%u,\"copy_checks\":%u,\"payload_checks\":%u,\"report_bytes\":%zu,\"serial_report_bytes\":%zu,\"native_operations\":0}\n",Case,LoadCalls,RawCalls,mResult.HookStores,mSerial.Report.HookStores,mSerial.Report.Count,mResult.AuthEnteredMask,mResult.DtbPublicSuccess,CopyChecks,PayloadChecks,sizeof(mResult),sizeof(mSerial.Report));
}
