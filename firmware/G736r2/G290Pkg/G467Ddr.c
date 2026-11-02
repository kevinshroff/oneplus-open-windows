/* SPDX-License-Identifier: MIT
 * Same exact G465 getter ABI with G417-style bounded loaded-provider binding.
 * No provider loading, frequency method, NPA, SMC or raw MMIO operation.
 */
#include "G467Ddr.h"
#include <Protocol/LoadedImage.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include "OpenSha256.h"
#include "G467DdrPins.h"
typedef struct G467_PROTOCOL G467_PROTOCOL;
typedef EFI_STATUS(EFIAPI*GET_DETAILS)(G467_PROTOCOL*,VOID*);
struct G467_PROTOCOL {UINT64 Revision;GET_DETAILS GetDDRDetails;};
static EFI_GUID mDdrGuid={0x1a7c0eb8,0x5646,0x45f7,{0xab,0x20,0xea,0xe5,0xda,0x46,0x40,0xa2}};
static UINT16 U16(CONST VOID*p){UINT16 v;CopyMem(&v,p,2);return v;}
static UINT32 U32(CONST VOID*p){UINT32 v;CopyMem(&v,p,4);return v;}
static UINT64 U64(CONST VOID*p){UINT64 v;CopyMem(&v,p,8);return v;}
static BOOLEAN In(UINTN base,UINTN bytes,UINTN at,UINTN n){return n<=bytes&&at>=base&&at-base<=bytes-n;}
static EFI_STATUS Bind(G467_PROTOCOL*p,G467_DDR_REPORT*r){
 EFI_HANDLE*h=NULL;UINTN count=0,found=0,base=0,bytes=0;EFI_STATUS st;
 EFI_LOADED_IMAGE_PROTOCOL*li=NULL;UINTN get=(UINTN)p->GetDDRDetails;
 r->Stage=2;r->ProtocolPa=(UINTN)p;r->Details.ProtocolRevision=p->Revision;
 if(p->Revision!=G465_DDR_REVISION||!get)return EFI_UNSUPPORTED;
 st=gBS->LocateHandleBuffer(ByProtocol,&gEfiLoadedImageProtocolGuid,NULL,&count,&h);
 if(st!=EFI_SUCCESS)return st;
 if(count>256||!h){if(h)FreePool(h);return EFI_UNSUPPORTED;}
 for(UINTN j=0;j<count;j++){
  st=gBS->HandleProtocol(h[j],&gEfiLoadedImageProtocolGuid,(VOID**)&li);
  if(st!=EFI_SUCCESS||!li||!li->ImageBase||li->ImageSize>MAX_UINTN)continue;
  if(In((UINTN)li->ImageBase,(UINTN)li->ImageSize,get,4)){found++;base=(UINTN)li->ImageBase;bytes=(UINTN)li->ImageSize;}
 }
 FreePool(h);if(found!=1)return EFI_NOT_FOUND;
 r->ProviderBase=base;r->ProviderBytes=bytes;
 if(bytes<0xb000||bytes>0x100000||base>MAX_UINTN-bytes)return EFI_BAD_BUFFER_SIZE;
 if((UINTN)p!=base+0x90c8||get!=base+0x163c)return EFI_UNSUPPORTED;
 r->GetterRva=(UINT32)(get-base);r->IdentityMask|=1;r->Stage=3;
 if(U16((VOID*)base)!=0x5a4d)return EFI_COMPROMISED_DATA;
 UINTN pe=U32((VOID*)(base+60));
 if(pe!=0xe58||!In(base,bytes,base+pe,0x180))return EFI_COMPROMISED_DATA;
 UINT8*q=(UINT8*)(base+pe);UINT16 opt=U16(q+20);
 if(U32(q)!=0x4550||U16(q+4)!=0xaa64||U16(q+6)!=3||opt!=0xf0||U16(q+24)!=0x20b||
    U64(q+24+24)!=(UINT64)base||U32(q+24+56)!=0xb000||U16(q+24+68)!=11)return EFI_UNSUPPORTED;
 UINT8*s=q+24+opt;
 if(!In(base,bytes,(UINTN)s,120)||CompareMem(s,".text",5)||U32(s+8)!=0x8000||U32(s+12)!=0x1000||U32(s+36)!=0x60000020||
    CompareMem(s+40,".data",5)||U32(s+48)!=0x1000||U32(s+52)!=0x9000||U32(s+76)!=0xc0000040||
    CompareMem(s+80,".reloc",6)||U32(s+88)!=0x1000||U32(s+92)!=0xa000||U32(s+116)!=0x42000040)return EFI_UNSUPPORTED;
 r->IdentityMask|=2;r->Stage=4;
 UINT8*text=AllocatePool(0x8000);if(!text)return EFI_OUT_OF_RESOURCES;
 CopyMem(text,(VOID*)(base+0x1000),0x8000);
 for(UINTN j=0;j<sizeof(mDdrTextRelocs)/sizeof(mDdrTextRelocs[0]);j++){
  UINTN off=mDdrTextRelocs[j];UINT64 value=U64(text+off)-base;CopyMem(text+off,&value,8);
 }
 OpenShaAll(text,0x8000,r->NormalizedTextSha);FreePool(text);
 if(CompareMem(r->NormalizedTextSha,mDdrTextSha,32))return EFI_SECURITY_VIOLATION;
 r->IdentityMask|=4;
 /* Recheck the exact same protocol object/callback immediately before call;
  * never re-Locate into a different provider after this identity proof. */
 if(p->Revision!=G465_DDR_REVISION||(UINTN)p->GetDDRDetails!=base+0x163c)return EFI_NOT_READY;
 r->IdentityMask|=8;return EFI_SUCCESS;
}
static EFI_STATUS Capture(UINT64 generation,G467_DDR_REPORT*r){
 G467_PROTOCOL*p=NULL;EFI_STATUS st;G465_DDR_REPORT*d=&r->Details;
 struct {UINT64 Before;UINT8 Raw[G465_DDR_DETAILS_BYTES];UINT64 After;} Buffer;
 if(!generation||!gBS)return EFI_INVALID_PARAMETER;
 r->Stage=1;st=gBS->LocateProtocol(&mDdrGuid,NULL,(VOID**)&p);d->LocateStatus=st;
 if(st!=EFI_SUCCESS)return st;if(!p)return EFI_PROTOCOL_ERROR;
 st=Bind(p,r);if(st!=EFI_SUCCESS)return st;
 Buffer.Before=Buffer.After=0x4764653643616e79ULL;SetMem(Buffer.Raw,sizeof(Buffer.Raw),0xff);
 r->Stage=5;d->Attempted=1;st=p->GetDDRDetails(p,Buffer.Raw);d->DetailsStatus=st;
 if(st!=EFI_SUCCESS)return st;
 if(Buffer.Before!=0x4764653643616e79ULL||Buffer.After!=0x4764653643616e79ULL)return EFI_COMPROMISED_DATA;
 CopyMem(d->RawDetails,Buffer.Raw,sizeof(Buffer.Raw));d->Manufacturer=Buffer.Raw[0];d->RawDeviceType=Buffer.Raw[1];
 if(d->RawDeviceType!=7&&d->RawDeviceType!=8)return EFI_UNSUPPORTED;
 d->Accepted=1;r->Stage=6;return EFI_SUCCESS;
}
VOID G467CaptureDdr(EFI_HANDLE Owner,UINT64 Generation,G467_DDR_REPORT*r){
 ZeroMem(r,sizeof(*r));r->Header.Signature=SIGNATURE_32('O','G','D','D');r->Header.Length=sizeof(*r);
 r->Header.Revision=1;CopyMem(r->Header.OemId,"OPEN  ",6);r->Header.OemTableId=SIGNATURE_64('G','4','6','7','D','D','R',' ');
 r->Header.OemRevision=1;r->Header.CreatorId=SIGNATURE_32('O','P','E','N');r->Header.CreatorRevision=1;
 r->Version=1;r->OwnerImage=(UINTN)Owner;CopyMem(r->ExpectedProviderFileSha,mDdrFileSha,32);
 r->Details.Size=sizeof(r->Details);r->Details.Version=1;r->Details.Generation=Generation;
 r->Details.LocateStatus=r->Details.DetailsStatus=EFI_NOT_READY;r->Details.RawDeviceType=r->Details.Manufacturer=MAX_UINT32;
 SetMem(r->Details.RawDetails,sizeof(r->Details.RawDetails),0xff);
 r->Status=Capture(Generation,r);r->Header.Checksum=CalculateCheckSum8((UINT8*)r,sizeof(*r));
}
