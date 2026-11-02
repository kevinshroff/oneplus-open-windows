/* Actual adapter and real UEFI headers; all firmware services are models. */
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
static UINT8 PilImage[0x42000] __attribute__((aligned(4096)));
static UINT8 ScmImage[0x42000] __attribute__((aligned(4096)));
static G128_REPORT Meta;
static const char *Case;
static unsigned LoadCalls,RawCalls,Published,Allocs,Frees,ScmLocates,Started,Raises;
static UINT8 DspWire[4096],SerialWire[4096];static UINTN DspBytes,SerialBytes;
static int Is(const char*s){return strcmp(Case,s)==0;}
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
VOID EFIAPI MemoryFence(VOID){}
VOID*EFIAPI AllocateZeroPool(UINTN n){Allocs++;return calloc(1,n);}
VOID EFIAPI FreePool(VOID*p){assert(p);Frees++;free(p);}
UINTN EFIAPI Print(CONST CHAR16*fmt,...){(void)fmt;return 0;}
static VOID Log(CONST CHAR8*fmt,...){(void)fmt;}
BOOLEAN OpenKernelWindowInventoryComplete(VOID){return!Is("inventory-refused");}
CONST G128_REPORT*OpenGetPilMetadataReport(VOID){return Is("metadata-null")?NULL:&Meta;}
OP_U64 OpenDspCurrentEl(void){return Is("EL0")?0:Is("EL3")?3:Is("EL2")?2:1;}
OP_U64 OpenDspAt(void*ctx,OP_U64 at,unsigned write){
 assert(*(UINT64*)ctx==OpenDspCurrentEl());
 if(Is("CPU-read-fault")&&!write)return 1;if(Is("CPU-write-fault")&&write)return 1;
 if(Is("CPU-alias"))return(0xffULL<<56)|(at+4096);if(Is("CPU-device"))return at;
 if(Is("stale-before-hook")&&at==0xae87f000&&write)SetQ(ScmImage+0xe178,Other());
 return(0xffULL<<56)|at;
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
 assert(self==&Acpi);EFI_ACPI_DESCRIPTION_HEADER*h=table;UINT8 sum=0;for(UINTN i=0;i<n;i++)sum=(UINT8)(sum+((UINT8*)table)[i]);assert(!sum&&h->Length==n&&h->OemRevision==136);Published++;
 if(h->Signature==SIGNATURE_32('O','A','D','P')){
  assert(n==sizeof(*h)+sizeof(mResult)&&!memcmp(h+1,&mResult,sizeof(mResult)));memcpy(DspWire,table,n);DspBytes=n;if(Is("DSP-publication-fail"))return EFI_DEVICE_ERROR;
 }else{
  assert(h->Signature==SIGNATURE_32('O','S','E','R')&&n==sizeof(*h)+sizeof(mSerial.Report)&&!memcmp(h+1,&mSerial.Report,sizeof(mSerial.Report)));memcpy(SerialWire,table,n);SerialBytes=n;if(Is("serial-publication-fail"))return EFI_DEVICE_ERROR;
 }
 *key=136;return EFI_SUCCESS;
}
UINT64 RawSip(VOID*self,UINT32 command,UINT32 param,OP_U64*args,OP_U64*out){
 assert(self==Scm()&&command!=0x42000205&&command!=0x42000206&&args&&args[9]==0x99);
 unsigned step=RawCalls++;assert(step<2&&command==0x42000201+step&&param==(step?3:0x82));
 assert(Q(ScmImage+0xe580)==(UINTN)&mSerialProxy);
 out[0]=1;out[1]=0;out[2]=0x2020;out[3]=0x3030;
 if(Is("serial-change-after-init")&&!step)SetQ(ScmImage+0xe580,Other());
 if((Is("service-init")&&!step)||(Is("service-mem")&&step)){out[1]=~6ULL;return EFI_SUCCESS;}
 if((Is("header-init")&&!step)||(Is("header-mem")&&step)){out[0]=0;return EFI_SUCCESS;}
 int fail=(Is("error-init")&&!step)||(step&&(Is("error-mem")||Is("error-unsupported")||Is("error-already")||Is("serial-restore-write-fail")||Is("restore-write-fail")||Is("serial-change-after-mem")||Is("slot-change-after-mem")||Is("bad-log")||Is("nonstack-log")||Is("oversized-log")||Is("other-serial")));
 if(!fail)return EFI_SUCCESS;
 UINT32 raw=Is("error-unsupported")?0xffffffffu:0xfffffffeu;char text[512];
 int length=snprintf(text,sizeof(text),"tz_armv8_smc_call failed, TzStatus = 0x%X,  SmcId = 0x%X  \r\n",raw,command);assert(length>0&&(UINTN)length<sizeof(text));
 if(Is("bad-log"))text[40]='?';
 G136_SERIAL_PROXY*proxy=(VOID*)(UINTN)Q(ScmImage+0xe580);
 if(Is("other-serial")){assert(!proxy->Poll()&&!proxy->Read((VOID*)(UINTN)0xc7b7000,16));}
 if(Is("nonstack-log")){static const char nonstack[]="tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x42000202  \r\n";proxy->Write(nonstack,sizeof(nonstack)-1);}
 else proxy->Write(text,Is("oversized-log")?513:(UINTN)length);
 out[0]=Is("error-already")?~12ULL:0;out[1]=out[2]=out[3]=0;
 if(Is("serial-change-after-mem"))SetQ(ScmImage+0xe580,Other());
 if(Is("slot-change-after-mem"))SetQ(ScmImage+0xe178,Other());
 return Is("error-unsupported")?EFI_UNSUPPORTED:Is("error-already")?EFI_ALREADY_STARTED:EFI_DEVICE_ERROR;
}
UINT64 LoadCfg(UINTN method,VOID*config){
 assert(method==(UINTN)PilImage+0x172c&&LoadCalls++==0);UINT8 expected[568];memcpy(expected,FixtureConfig[0],568);UINT64 base=0xa9f80000;memcpy(expected+0xf0,&base,8);expected[0x102]=1;assert(!memcmp(config,expected,sizeof expected));
 if(Is("loader-no-PAS"))return EFI_SUCCESS;
 for(unsigned step=0;step<3;step++){
  OP_U64 args[10]={36,step==0?0x38000000:step==1?base:0,step==1?0x80000:0,0,0,0,0,0,0,0x99},out[4]={0};
  typedef UINT64(EFIAPI*CALL)(VOID*,UINT32,UINT32,OP_U64*,OP_U64*);
  UINT64 s=((CALL)(UINTN)Q(ScmImage+0xe178))(Scm(),step==2?0x42000205:0x42000201+step,step==0?0x82:step==1?3:1,args,out);
  if(s)return EFI_LOAD_ERROR;
 }
 assert(!"Diagnostic must stop before AUTH");return EFI_SUCCESS;
}
int main(int argc,char**argv){
 assert(argc==2||argc==3);Case=argv[1];Bs.LocateProtocol=Locate;Bs.LocateHandleBuffer=Handles;Bs.HandleProtocol=Handle;Bs.RaiseTPL=Raise;Bs.RestoreTPL=Restore;Acpi.InstallAcpiTable=Install;
 for(unsigned i=0;i<2;i++){Gop[i].Mode=&Mode[i];Mode[i].FrameBufferBase=0xb8000000;Mode[i].FrameBufferSize=0x2b00000;}
 if(Is("GOP-overlap"))Mode[0].FrameBufferBase=0xa9f80000;if(Is("GOP-second-overlap"))Mode[1].FrameBufferBase=0xa9f80000;if(Is("GOP-overflow")){Mode[0].FrameBufferBase=~7ULL;Mode[0].FrameBufferSize=16;}
 Meta.Size=sizeof(Meta);Meta.Version=1;Meta.Magic=G128_MAGIC;Meta.Flags=0x7ff;Meta.ScmABI=2;Meta.ImagesAttempted=2;Meta.ImageBase[0]=(UINTN)PilImage;Meta.ImageBase[1]=(UINTN)ScmImage;Meta.ScmTableRva=0xe140;Meta.ScmFunctionRva=0x3f94;memcpy(Meta.Config,FixtureConfig,sizeof(Meta.Config));
 SetQ(PilImage+0x16188,0x10004);SetQ(PilImage+0x16198,(UINTN)PilImage+0x172c);SetQ(ScmImage+0xe140,0x40001);SetQ(ScmImage+0xe178,Original());
 UINT64 saved=Is("cached-serial")?0x12345678:Is("already-proxy")?(UINTN)&mSerialProxy:0;SetQ(ScmImage+0xe580,saved);
 if(Is("metadata-size"))Meta.Size--;if(Is("metadata-magic"))Meta.Magic=0;if(Is("metadata-status"))Meta.Status[0]=EFI_DEVICE_ERROR;if(Is("metadata-flags"))Meta.Flags^=2;if(Is("metadata-legacy"))Meta.ScmABI=1;if(Is("metadata-attempts"))Meta.ImagesAttempted=1;if(Is("metadata-PAS-count"))Meta.RequestedPasStages=1;
 if(Is("PIL-revision"))SetQ(Pil(),0);if(Is("PIL-method"))SetQ(PilImage+0x16198,(UINTN)PilImage+0x1708);if(Is("SCM-revision"))SetQ(Scm(),0);if(Is("SCM-method"))SetQ(ScmImage+0xe178,Other());
 if(Is("config-base"))Meta.Config[0][0xf0]^=1;if(Is("config-backup"))Meta.Config[1][0x114]=1;if(Is("config-postimage"))Meta.Config[1][0x1b4]=1;
 BOOLEAN mayContinue=FALSE;Started=1;EFI_STATUS s=OpenRunGuardedAdsp(!Is("source-refused"),Log,&mayContinue);
 assert(Published==2&&Allocs==Frees&&mResult.FinalStatus==s&&LoadCalls<=1&&RawCalls<=2&&!mResult.AuthEnteredMask&&!mResult.AuthAcceptedMask&&!mSerial.Report.Active&&!mSerial.Report.PendingCommand);
 assert(mSerial.Report.OriginalCalls==RawCalls&&mSerial.Report.Count<=1);
 if(Is("success")||Is("EL2")||Is("cached-serial")||Is("DSP-publication-fail")||Is("serial-publication-fail")){
  assert(s==EFI_ABORTED&&mayContinue&&LoadCalls==1&&RawCalls==2&&mResult.Fault==OP_DIAGNOSTIC_STOP&&mResult.Phase[0]==2&&mSerial.Report.DiagnosticStop&&!mSerial.Report.Count&&mResult.Flags==255&&mResult.HookStores==2&&mSerial.Report.HookStores==2);
 }else if(Is("error-init")||Is("error-mem")||Is("error-unsupported")||Is("error-already")||Is("other-serial")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&RawCalls==(Is("error-init")?1u:2u)&&mResult.Fault==OP_TRANSPORT&&mSerial.Report.Count==1&&mSerial.Report.Records[0].RawStatus==(Is("error-unsupported")?0xffffffffu:0xfffffffeu));
  assert(mSerial.Report.Records[0].Sequence==(Is("error-init")?0u:1u)&&mSerial.Report.Records[0].ApiStatus==mResult.Records[mSerial.Report.Records[0].Sequence].OriginalStatus);
  if(Is("other-serial"))assert(mSerial.Report.OtherCalls==2);
 }else if(Is("bad-log")||Is("nonstack-log")||Is("oversized-log")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&RawCalls==2&&mSerial.Report.Rejected==1&&!mSerial.Report.Count);
 }else if(Is("service-init")||Is("service-mem")||Is("header-init")||Is("header-mem")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&RawCalls==((Is("service-init")||Is("header-init"))?1u:2u)&&!mSerial.Report.Count);
 }else if(Is("serial-change-after-init")){
  assert(!mayContinue&&mResult.FatalRestore&&mSerial.Report.FatalRestore&&RawCalls==1&&mResult.Fault==OP_OWNERSHIP&&!mResult.Records[1].Entered);
 }else if(Is("serial-restore-write-fail")||Is("serial-change-after-mem")){
  assert(!mayContinue&&mResult.FatalRestore&&mSerial.Report.FatalRestore&&RawCalls==2&&mSerial.Report.Count==1);
 }else if(Is("restore-write-fail")||Is("slot-change-after-mem")){
  assert(!mayContinue&&mResult.FatalRestore&&!mSerial.Report.FatalRestore&&RawCalls==2);
 }else if(Is("serial-stale-before-hook")||Is("stale-before-hook")||Is("protocol-restore-changed")||Is("already-proxy")){
  assert(!mayContinue&&mResult.FatalRestore&&!RawCalls&&!LoadCalls);
 }else if(Is("serial-hook-write-fail")||Is("hook-write-fail")||Is("loader-no-PAS")){
  assert(s==EFI_DEVICE_ERROR&&mayContinue&&!RawCalls&&LoadCalls==(Is("loader-no-PAS")?1u:0u));
 }else assert(s!=EFI_SUCCESS&&mayContinue&&!LoadCalls&&!RawCalls&&!mResult.HookStores&&!mSerial.Report.HookStores);
 if(mayContinue&&mSerial.Report.HookStores)assert(Q(ScmImage+0xe580)==saved&&mSerial.Report.RestoreStatus==EFI_SUCCESS);
 if(mayContinue&&mResult.HookStores)assert(Q(ScmImage+0xe178)==Original());
 BOOLEAN before=mayContinue;unsigned calls=RawCalls;assert(OpenRunGuardedAdsp(TRUE,Log,&mayContinue)==EFI_ALREADY_STARTED&&mayContinue==before&&RawCalls==calls&&Published==2);
 if(argc==3){char path[2048];snprintf(path,sizeof path,"%s-DSP.bin",argv[2]);FILE*f=fopen(path,"wb");assert(f&&fwrite(DspWire,1,DspBytes,f)==DspBytes&&!fclose(f));snprintf(path,sizeof path,"%s-OSER.bin",argv[2]);f=fopen(path,"wb");assert(f&&fwrite(SerialWire,1,SerialBytes,f)==SerialBytes&&!fclose(f));}
 printf("{\"passed\":true,\"case\":\"%s\",\"PIL_calls\":%u,\"original_SCM_calls_modeled\":%u,\"SCM_slot_stores\":%u,\"serial_cache_stores\":%u,\"captured_errors\":%u,\"AUTH_forwarded\":0,\"report_bytes\":%zu,\"serial_report_bytes\":%zu,\"native_operations\":0}\n",Case,LoadCalls,RawCalls,mResult.HookStores,mSerial.Report.HookStores,mSerial.Report.Count,sizeof(mResult),sizeof(mSerial.Report));
}
