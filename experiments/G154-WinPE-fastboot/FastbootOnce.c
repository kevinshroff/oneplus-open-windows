// One-shot pre-OS reset helper. No raw-disk, GPT, PAS or direct MMIO access.
// The native installer preserves the exact Windows loader in G154.ORIG.
#include <Uefi.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DevicePath.h>
#include <Guid/FileInfo.h>

STATIC VOID *CopyMem(VOID *D, CONST VOID *S, UINTN N) { UINT8 *d=D; CONST UINT8 *s=S; for(UINTN i=0;i<N;i++)d[i]=s[i];return D; }
STATIC VOID *ZeroMem(VOID *D, UINTN N) { UINT8 *d=D;for(UINTN i=0;i<N;i++)d[i]=0;return D; }
STATIC INTN CompareMem(CONST VOID *A, CONST VOID *B, UINTN N) { CONST UINT8 *a=A,*b=B;for(UINTN i=0;i<N;i++)if(a[i]!=b[i])return a[i]<b[i]?-1:1;return 0; }
#include "OpenSha256.h"
#include "FastbootIdentities.h"

STATIC EFI_GUID LoadedGuid=EFI_LOADED_IMAGE_PROTOCOL_GUID;
STATIC EFI_GUID FsGuid=EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
STATIC EFI_GUID DpGuid=EFI_DEVICE_PATH_PROTOCOL_GUID;
STATIC EFI_GUID InfoGuid=EFI_FILE_INFO_ID;
STATIC EFI_GUID ResetFileGuid={0x3ae17db7,0x3cc5,0x4b89,{0x93,0x04,0x95,0x49,0x21,0x10,0x57,0xef}};
STATIC EFI_GUID PmicGuid={0x9ba45b66,0xefa4,0x441c,{0xa3,0xe4,0xed,0x22,0x24,0x78,0x6b,0xe2}};
STATIC EFI_GUID EspGuid={0x5982c0bf,0xb83f,0x025d,{0x43,0x54,0x68,0x00,0x9b,0xa0,0xa5,0xd1}};

typedef struct { UINT8 Magic[8]; UINT64 Phase; EFI_STATUS Status; UINT64 ResetImage; UINT64 RuntimeReset; UINT8 Reserved[24]; } RECEIPT;
_Static_assert(sizeof(RECEIPT)==64,"receipt ABI");
STATIC EFI_BOOT_SERVICES *Bs;
STATIC EFI_SYSTEM_TABLE *St;
STATIC EFI_FILE_PROTOCOL *Root;
STATIC EFI_HANDLE Self;
STATIC EFI_LOADED_IMAGE_PROTOCOL *SelfImage;

STATIC VOID Say(CHAR16 *S) { if(St->ConOut)St->ConOut->OutputString(St->ConOut,S); }
STATIC VOID Receipt(UINT64 Phase,EFI_STATUS Status,UINTN ResetImage) {
  EFI_FILE_PROTOCOL *F=NULL;RECEIPT R;ZeroMem(&R,sizeof(R));CopyMem(R.Magic,"G154RST1",8);R.Phase=Phase;R.Status=Status;R.ResetImage=ResetImage;R.RuntimeReset=(UINTN)St->RuntimeServices->ResetSystem;
  // The installer pre-creates this exact 64-byte receipt. Never create it here.
  if(!Root||EFI_ERROR(Root->Open(Root,&F,L"\\EFI\\BOOT\\G154.STATUS",EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE,0)))return;
  UINTN N=sizeof(R);if(!EFI_ERROR(F->SetPosition(F,0))&&!EFI_ERROR(F->Write(F,&N,&R))&&N==sizeof(R))F->Flush(F);F->Close(F);
}
STATIC EFI_STATUS Info(EFI_FILE_PROTOCOL *F,EFI_FILE_INFO *I,UINTN Capacity) { UINTN N=Capacity;ZeroMem(I,Capacity);return F->GetInfo(F,&InfoGuid,&N,I); }
STATIC BOOLEAN EspPath(EFI_DEVICE_PATH_PROTOCOL *Dp) {
  UINTN Off=0,Found=0;
  while(Off+4<=512) {
    EFI_DEVICE_PATH_PROTOCOL *D=(VOID *)((UINT8 *)Dp+Off);UINTN N=(UINTN)D->Length[0]|((UINTN)D->Length[1]<<8);
    if(N<4||N>512-Off)return FALSE;
    if(D->Type==END_DEVICE_PATH_TYPE)return Found==1&&D->SubType==END_ENTIRE_DEVICE_PATH_SUBTYPE&&N==4;
    if(D->Type==MEDIA_DEVICE_PATH&&D->SubType==MEDIA_HARDDRIVE_DP) {
      if(N!=sizeof(HARDDRIVE_DEVICE_PATH))return FALSE;HARDDRIVE_DEVICE_PATH *H=(VOID *)D;
      if(H->PartitionNumber!=14||H->PartitionStart!=0x4582ecULL||H->PartitionSize!=0x71bb90fULL||H->MBRType!=2||H->SignatureType!=2||CompareMem(H->Signature,&EspGuid,16))return FALSE;
      Found++;
    }
    Off+=N;
  }return FALSE;
}
STATIC BOOLEAN FvResetPath(EFI_DEVICE_PATH_PROTOCOL *Dp) {
  if(!Dp)return FALSE;UINTN Off=0,Found=0;
  while(Off+4<=512) {
    EFI_DEVICE_PATH_PROTOCOL *D=(VOID *)((UINT8 *)Dp+Off);UINTN N=(UINTN)D->Length[0]|((UINTN)D->Length[1]<<8);
    if(N<4||N>512-Off)return FALSE;
    if(D->Type==END_DEVICE_PATH_TYPE)return Found==1&&D->SubType==END_ENTIRE_DEVICE_PATH_SUBTYPE&&N==4;
    if(D->Type==MEDIA_DEVICE_PATH&&D->SubType==MEDIA_PIWG_FW_FILE_DP) {if(N!=20||CompareMem((UINT8 *)D+4,&ResetFileGuid,16))return FALSE;Found++;}
    Off+=N;
  }return FALSE;
}
STATIC EFI_STATUS ReadOriginal(VOID **Data) {
  EFI_FILE_PROTOCOL *F=NULL;EFI_STATUS S;UINT8 Ibuf[512];EFI_FILE_INFO *I=(VOID *)Ibuf;UINT8 H[32];
  S=Root->Open(Root,&F,L"\\EFI\\BOOT\\G154.ORIG",EFI_FILE_MODE_READ,0);if(EFI_ERROR(S))return S;
  S=Info(F,I,sizeof(Ibuf));if(EFI_ERROR(S)||I->FileSize!=ORIGINAL_BYTES||(I->Attribute&EFI_FILE_DIRECTORY)){F->Close(F);return EFI_COMPROMISED_DATA;}
  S=Bs->AllocatePool(EfiLoaderData,ORIGINAL_BYTES,Data);if(EFI_ERROR(S)){F->Close(F);return S;}
  UINTN N=ORIGINAL_BYTES;S=F->Read(F,&N,*Data);F->Close(F);if(EFI_ERROR(S)||N!=ORIGINAL_BYTES)return EFI_DEVICE_ERROR;
  OpenShaAll(*Data,ORIGINAL_BYTES,H);return CompareMem(H,OriginalHash,32)?EFI_COMPROMISED_DATA:EFI_SUCCESS;
}
STATIC EFI_STATUS RestoreOriginal(VOID *Data) {
  EFI_FILE_PROTOCOL *F=NULL;EFI_STATUS S;UINT8 Ibuf[512];EFI_FILE_INFO *I=(VOID *)Ibuf;VOID *Verify=NULL;UINT8 H[32];
  S=Root->Open(Root,&F,L"\\EFI\\BOOT\\BOOTAA64.EFI",EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE,0);if(EFI_ERROR(S))return S;
  S=Info(F,I,sizeof(Ibuf));if(EFI_ERROR(S)||I->FileSize==0||I->FileSize>0x100000||(I->Attribute&EFI_FILE_DIRECTORY)){F->Close(F);return EFI_COMPROMISED_DATA;}
  S=F->SetPosition(F,0);UINTN N=ORIGINAL_BYTES;if(!EFI_ERROR(S))S=F->Write(F,&N,Data);if(!EFI_ERROR(S)&&N!=ORIGINAL_BYTES)S=EFI_DEVICE_ERROR;
  if(!EFI_ERROR(S)){I->FileSize=ORIGINAL_BYTES;S=F->SetInfo(F,&InfoGuid,(UINTN)I->Size,I);}
  if(!EFI_ERROR(S))S=F->Flush(F);
  if(!EFI_ERROR(S))S=Bs->AllocatePool(EfiLoaderData,ORIGINAL_BYTES,&Verify);
  if(!EFI_ERROR(S))S=F->SetPosition(F,0);
  N=ORIGINAL_BYTES;if(!EFI_ERROR(S))S=F->Read(F,&N,Verify);
  if(!EFI_ERROR(S)&&N!=ORIGINAL_BYTES)S=EFI_DEVICE_ERROR;
  if(!EFI_ERROR(S)){OpenShaAll(Verify,ORIGINAL_BYTES,H);if(CompareMem(H,OriginalHash,32))S=EFI_COMPROMISED_DATA;}
  if(Verify)Bs->FreePool(Verify);EFI_STATUS Close=F->Close(F);return EFI_ERROR(S)?S:Close;
}
STATIC EFI_STATUS FindReset(VOID **Base) {
  EFI_HANDLE *Handles=NULL;UINTN Count=0,Matches=0;EFI_STATUS S=Bs->LocateHandleBuffer(ByProtocol,&LoadedGuid,NULL,&Count,&Handles);if(EFI_ERROR(S))return S;
  if(Count>256){Bs->FreePool(Handles);return EFI_COMPROMISED_DATA;}
  VOID *Text=NULL;S=Bs->AllocatePool(EfiLoaderData,RESET_TEXT_BYTES,&Text);if(EFI_ERROR(S)){Bs->FreePool(Handles);return S;}
  for(UINTN i=0;i<Count;i++) {
    EFI_LOADED_IMAGE_PROTOCOL *L=NULL;if(EFI_ERROR(Bs->HandleProtocol(Handles[i],&LoadedGuid,(VOID **)&L))||!L||L->ImageSize!=RESET_IMAGE_BYTES||!L->ImageBase||!FvResetPath(L->FilePath))continue;
    UINT8 *B=L->ImageBase;CopyMem(Text,B+0x1000,RESET_TEXT_BYTES);
    for(UINTN j=0;j<sizeof(ResetTextRelocations)/sizeof(ResetTextRelocations[0]);j++){UINT64 V;CopyMem(&V,(UINT8 *)Text+ResetTextRelocations[j],8);V-=(UINTN)B;CopyMem((UINT8 *)Text+ResetTextRelocations[j],&V,8);}
    UINT8 H[32];OpenShaAll(Text,RESET_TEXT_BYTES,H);if(CompareMem(H,ResetTextHash,32))continue;
    // Exact recovered pre-boot state: initialized BootServices and runtime flag.
    UINTN DriverBs;CopyMem(&DriverBs,B+0x71b0,sizeof(DriverBs));if(DriverBs!=(UINTN)Bs||B[0x71bc]!=0)continue;
    *Base=B;Matches++;
  }
  Bs->FreePool(Text);Bs->FreePool(Handles);if(Matches!=1)return EFI_UNSUPPORTED;
  VOID *Pmic=NULL;S=Bs->LocateProtocol(&PmicGuid,NULL,&Pmic);if(EFI_ERROR(S)||!Pmic)return EFI_UNSUPPORTED;
  UINTN WriteSpare;CopyMem(&WriteSpare,(UINT8 *)Pmic+0x28,sizeof(WriteSpare));return WriteSpare?EFI_SUCCESS:EFI_UNSUPPORTED;
}
STATIC EFI_STATUS ChainWindows(VOID *Data) {
  // Preserve the full original file path and device while loading verified bytes.
  EFI_DEVICE_PATH_PROTOCOL *D=NULL;EFI_STATUS S=Bs->HandleProtocol(SelfImage->DeviceHandle,&DpGuid,(VOID **)&D);if(EFI_ERROR(S)||!D)return S;
  UINTN DeviceBytes=0;while(DeviceBytes+4<=512){EFI_DEVICE_PATH_PROTOCOL *N=(VOID *)((UINT8 *)D+DeviceBytes);UINTN Z=N->Length[0]|((UINTN)N->Length[1]<<8);if(Z<4||Z>512-DeviceBytes)return EFI_COMPROMISED_DATA;if(N->Type==END_DEVICE_PATH_TYPE)break;DeviceBytes+=Z;}
  if(DeviceBytes+4>512)return EFI_COMPROMISED_DATA;
  STATIC CONST CHAR16 Name[]=L"\\EFI\\BOOT\\BOOTAA64.EFI";
  UINTN FileBytes=4+sizeof(Name),Total=DeviceBytes+FileBytes+4;UINT8 *Path=NULL;S=Bs->AllocatePool(EfiLoaderData,Total,(VOID **)&Path);if(EFI_ERROR(S))return S;
  CopyMem(Path,D,DeviceBytes);Path[DeviceBytes]=MEDIA_DEVICE_PATH;Path[DeviceBytes+1]=MEDIA_FILEPATH_DP;Path[DeviceBytes+2]=(UINT8)FileBytes;Path[DeviceBytes+3]=(UINT8)(FileBytes>>8);CopyMem(Path+DeviceBytes+4,Name,sizeof(Name));UINT8 End[4]={END_DEVICE_PATH_TYPE,END_ENTIRE_DEVICE_PATH_SUBTYPE,4,0};CopyMem(Path+Total-4,End,4);
  EFI_HANDLE Child=NULL;S=Bs->LoadImage(FALSE,Self,(VOID *)Path,Data,ORIGINAL_BYTES,&Child);Bs->FreePool(Path);Bs->FreePool(Data);if(!EFI_ERROR(S))S=Bs->StartImage(Child,NULL,NULL);return S;
}
EFI_STATUS EFIAPI EfiMain(EFI_HANDLE Image,EFI_SYSTEM_TABLE *SystemTable) {
  if(!SystemTable||SystemTable->Hdr.Signature!=EFI_SYSTEM_TABLE_SIGNATURE||!SystemTable->BootServices||!SystemTable->RuntimeServices)return EFI_UNSUPPORTED;
  Self=Image;St=SystemTable;Bs=St->BootServices;EFI_STATUS S=Bs->HandleProtocol(Self,&LoadedGuid,(VOID **)&SelfImage);if(EFI_ERROR(S)||!SelfImage||!SelfImage->DeviceHandle)return EFI_UNSUPPORTED;
  EFI_DEVICE_PATH_PROTOCOL *Dp=NULL;S=Bs->HandleProtocol(SelfImage->DeviceHandle,&DpGuid,(VOID **)&Dp);if(EFI_ERROR(S)||!Dp||!EspPath(Dp))return EFI_UNSUPPORTED;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs=NULL;S=Bs->HandleProtocol(SelfImage->DeviceHandle,&FsGuid,(VOID **)&Fs);if(EFI_ERROR(S)||!Fs)return EFI_UNSUPPORTED;
  S=Fs->OpenVolume(Fs,&Root);if(EFI_ERROR(S)||!Root)return EFI_UNSUPPORTED;
  Say(L"G154: restoring Windows loader before one-shot fastboot request.\r\n");VOID *Original=NULL;S=ReadOriginal(&Original);if(EFI_ERROR(S)){Receipt(1,S,0);Root->Close(Root);if(Original)Bs->FreePool(Original);return S;}
  S=RestoreOriginal(Original);Receipt(2,S,0);
  if(EFI_ERROR(S)){Say(L"G154: restore failed; continuing verified Windows loader from memory.\r\n");Root->Close(Root);Root=NULL;return ChainWindows(Original);}
  VOID *ResetBase=NULL;S=FindReset(&ResetBase);Receipt(3,S,(UINTN)ResetBase);
  if(EFI_ERROR(S)){Say(L"G154: firmware reset checks refused; continuing Windows.\r\n");Root->Close(Root);Root=NULL;return ChainWindows(Original);}
  Receipt(4,EFI_SUCCESS,(UINTN)ResetBase);Root->Close(Root);Root=NULL;Bs->FreePool(Original);
  Say(L"G154: Windows loader restored; requesting Qualcomm bootloader reset.\r\n");
  UINT8 ResetData[26];ZeroMem(ResetData,sizeof(ResetData));STATIC CONST CHAR16 Reason[]=L"RESET_PARAM";CopyMem(ResetData,Reason,sizeof(Reason));ResetData[24]=2;
  // Exact original ABL request, sent to the hash-qualified vendor ResetSystem.
  EFI_RESET_SYSTEM VendorReset=(EFI_RESET_SYSTEM)(UINTN)((UINT8 *)ResetBase+0x153c);
  VendorReset(EfiResetCold,EFI_INVALID_PARAMETER,25,ResetData);
  // ResetSystem is not allowed to return; no retry, PAS cleanup or direct MMIO.
  return EFI_DEVICE_ERROR;
}
