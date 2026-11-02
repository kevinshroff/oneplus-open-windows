/* Actual publication lifecycle, explicit service/formatter/AT models. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#undef NULL
#include "OpenPilInventory.c"
#include "OpenPilCpuInventory.c"
EFI_GUID gEfiAcpiTableProtocolGuid=EFI_ACPI_TABLE_PROTOCOL_GUID;
static EFI_BOOT_SERVICES Bs;
EFI_BOOT_SERVICES *gBS=&Bs;
static EFI_ACPI_TABLE_PROTOCOL Acpi;
static const char *Case;
static unsigned Allocations,Frees,Collections,Publications;
static P139_U64 Calls;
static unsigned char *Saved;
static size_t SavedBytes;
static int Is(const char *s){return strcmp(Case,s)==0;}
VOID *EFIAPI AllocateZeroPool(UINTN n)
{
 if((Is("text-pool-fail")&&n==REPORT_BYTES)||(Is("cpu-pool-fail")&&n==sizeof(P139_CPU_INVENTORY))||
    (Is("header-pool-fail")&&n!=REPORT_BYTES&&n!=sizeof(P139_CPU_INVENTORY)))return NULL;
 Allocations++;return calloc(1,n);
}
VOID EFIAPI FreePool(VOID *p){assert(p);Frees++;free(p);}
VOID *EFIAPI CopyMem(VOID *d,CONST VOID *s,UINTN n){return memcpy(d,s,n);}
static UINTN Format(CHAR8 *out,UINTN room,CONST CHAR8 *f,VA_LIST args)
{
 char fmt[2048];size_t n=0;
 for(unsigned i=0;f[i];i++){
  assert(n+5<sizeof fmt);
  if(f[i]=='%'&&f[i+1]=='a'){fmt[n++]='%';fmt[n++]='s';i++;}
  else if(f[i]=='%'&&f[i+1]=='r'){memcpy(fmt+n,"%lx",3);n+=3;i++;}
  else fmt[n++]=f[i];
 }
 fmt[n]=0;int result=vsnprintf(out,room,fmt,args);assert(result>=0);
 return (UINTN)result>=room?room-1:(UINTN)result;
}
UINTN EFIAPI AsciiVSPrint(CHAR8 *out,UINTN room,CONST CHAR8 *f,VA_LIST args){return Format(out,room,f,args);}
UINTN EFIAPI AsciiSPrint(CHAR8 *out,UINTN room,CONST CHAR8 *f,...)
{
 VA_LIST args;UINTN n;VA_START(args,f);n=Format(out,room,f,args);VA_END(args);return n;
}
VOID OpenAppendPilFootprint(OPEN_PIL_REPORT r)
{
 Collections++;
 r("OPEN-PIL-FOOTPRINT G139 version=1\nP139_proposed dtb=9E980000:80000 main=9EA00000:4880000 region_writes=0 PAS_requests=0\n");
 if(Is("text-clipped")){char line[101];memset(line,'x',100);line[100]=0;for(unsigned i=0;i<500;i++)r("%a\n",line);}
 r("P139_gop_status=0 count=2\nP139_gop index=0 base=B8000000 bytes=151C380 overlap=0\nP139_gop index=1 base=B8000000 bytes=151C380 overlap=0\nP139_gop_valid_rows=2\n");
 r("P139_DONE queries_complete=1 PAS_allowed=0 DMA_ownership=not_proved region_writes=0\n");
}
P139_U64 OpenDspCurrentEl(void){return Is("bad-el")?3:1;}
P139_U64 OpenDspAt(void *context,P139_U64 p,unsigned write)
{
 assert(*(P139_U64 *)context==1 && p==P139_WINDOW_START+(Calls/2)*4096 && write==(Calls&1));Calls++;
 if(Is("cpu-fault")&&Calls==1)return 1;
 if(Is("cpu-alias")&&Calls==2)return (p+4096)|0x4400000000000000ULL;
 if(Is("cpu-mixed-tags"))return p|(((Calls-1)/2+write)&255)<<56;
 return p|0x4400000000000000ULL;
}
static EFI_STATUS EFIAPI Locate(EFI_GUID *guid,VOID *reg,VOID **out)
{
 assert(guid==&gEfiAcpiTableProtocolGuid && reg==NULL);
 if(Is("acpi-error"))return EFI_NOT_FOUND;
 if(Is("acpi-warning"))return EFI_WARN_UNKNOWN_GLYPH;
 *out=Is("acpi-null")?NULL:&Acpi;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Install(EFI_ACPI_TABLE_PROTOCOL *self,VOID *p,UINTN n,UINTN *key)
{
 assert(self==&Acpi && n>36 && n<=REPORT_BYTES+36 && p && key);
 Publications++;Saved=malloc(n+1);assert(Saved);memcpy(Saved,p,n);Saved[n]=0;SavedBytes=n;*key=139;
 if(Is("install-error"))return EFI_DEVICE_ERROR;
 if(Is("install-warning"))return EFI_WARN_UNKNOWN_GLYPH;
 return EFI_SUCCESS;
}
int main(int argc,char **argv)
{
 EFI_STATUS status;assert(argc==2);Case=argv[1];Bs.LocateProtocol=Locate;Acpi.InstallAcpiTable=Install;
 status=OpenRunPilInventory();
 assert(Allocations==Frees);
 if(Is("text-pool-fail")){assert(status==EFI_OUT_OF_RESOURCES && !Calls && !Collections && !Publications);}
 else{
  assert(Collections==1);
  assert(Calls==((Is("cpu-pool-fail")||Is("bad-el"))?0:37376));
  if(Is("header-pool-fail"))assert(status==EFI_OUT_OF_RESOURCES && !Publications);
  else if(Is("acpi-error")||Is("acpi-null"))assert(status==EFI_NOT_FOUND && !Publications);
  else if(Is("acpi-warning"))assert(status==EFI_WARN_UNKNOWN_GLYPH && !Publications);
  else{
   assert(Publications==1 && Saved);
   assert(status==(Is("install-error")?EFI_DEVICE_ERROR:Is("install-warning")?EFI_WARN_UNKNOWN_GLYPH:EFI_SUCCESS));
   EFI_ACPI_DESCRIPTION_HEADER *h=(VOID *)Saved;unsigned char sum=0;
   for(size_t i=0;i<SavedBytes;i++)sum+=Saved[i];
   assert(sum==0 && h->Signature==SIGNATURE_32('O','P','I','L') && h->Length==SavedBytes && h->OemRevision==139);
   assert(memcmp(&h->OemTableId,"G139PIL1",8)==0);
   assert(strstr((char *)Saved+36,Is("text-clipped")?"G139_FINAL truncated=1":"G139_FINAL truncated=0"));
   if(Is("cpu-pool-fail"))assert(strstr((char *)Saved+36,"allocation_failed=1 queries=0"));
   if(Is("bad-el"))assert(strstr((char *)Saved+36,"el=3 complete=0 refusal=1 pages=0 queries=0"));
   if(Is("success")||Is("cpu-pool-fail")||Is("bad-el")||Is("text-clipped")||Is("cpu-fault")||Is("cpu-alias")||Is("cpu-mixed-tags")){
    char path[256];snprintf(path,sizeof path,"%s.bin",Case);FILE *f=fopen(path,"wb");assert(f);assert(fwrite(Saved,1,SavedBytes,f)==SavedBytes);assert(fclose(f)==0);
   }
  }
 }
 unsigned before=Allocations;assert(OpenRunPilInventory()==EFI_ALREADY_STARTED && Allocations==before);
 free(Saved);
 printf("{\"passed\":true,\"case\":\"%s\",\"AT_queries\":%llu,\"table_bytes\":%zu,\"allocations\":%u,\"native_operations\":0}\n",Case,Calls,SavedBytes,Allocations);
}
