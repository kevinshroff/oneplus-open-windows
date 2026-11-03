/* Source adapter for inclusion by the existing pre-EBS G289/G290 owner.
 * Requires unchanged G289_NPA, EFI_STATUS/types and BootServices owner lifetime.
 * No callable Windows protocol pointers, Complete/Delete or EBS request.
 * Raw type4/Ib1000000/Ab0 units are an accepted QTI-family inference;
 * NOT an exact matching assertion of Linux peak1000kB/s. */
#ifndef OPEN_QTB_WITNESS
#define OPEN_QTB_WITNESS 0
#endif
static VOID *mQtbTcuClient;
static UINT32 mQtbTcuAttempted,mQtbTcuReturned;
/* Caller owns current provider/version/pins and must call only BEFORE EBS,
 * with the resident source owner serialization already held. Embed attempted,
 * returned, pair/request and provider hashes in the new firmware receipt.
 * Stock request may block internally without bound; never claim outertimeout
 * can cancel it. Any created client and this resident image stay until reset. */
static EFI_STATUS QtbTcuKeepVote(G289_NPA *N,BOOLEAN ExitedBootServices)
{
#if !OPEN_QTB_WITNESS
 (VOID)N;(VOID)ExitedBootServices;return EFI_UNSUPPORTED;
#else
 typedef EFI_STATUS (*VECTOR)(VOID*,UINT32,CONST UINT32*);
 _Alignas(8) static CONST UINT32 Pair[2]={196,0};
 _Alignas(8) static CONST UINT32 Request[8]={4,0,1000000,0,0,0,0,0};
 UINT32 A=MAX_UINT32;EFI_STATUS E;VECTOR V;
 if(ExitedBootServices||mQtbTcuAttempted||mQtbTcuClient||!N||N->Version!=0x10003||!N->Available||!N->Create)return EFI_NOT_READY;
 V=*(VECTOR*)((UINT8*)N+144);if(!V)return EFI_UNSUPPORTED;
 mQtbTcuAttempted=1;
 E=N->Available("/icb/arbiter",&A);if(E||A)return E?E:EFI_NOT_READY;
 E=N->Create("/icb/arbiter","Open-QTB-gpu-tcu",0x400,sizeof(Pair),(VOID*)Pair,&mQtbTcuClient);
 if(E||!mQtbTcuClient)return E?E:EFI_DEVICE_ERROR;
 E=V(mQtbTcuClient,8,Request);if(!E)mQtbTcuReturned=1;
 return E;
#endif
}

/* Publish ONLY after the retained request returned success, before EBS.
 * Header/payload are an evidence receipt, never electrical-on/settled proof.
 * New immutable firmware identity and provider image pins must be root-reviewed
 * together with this table; table-embedded expectations are not attestation. */
#pragma pack(push,1)
typedef struct {
 EFI_ACPI_DESCRIPTION_HEADER Header;
 UINT32 Version,Master,Slave,Type;UINT64 Ib,Ab;UINT32 FamilyInference;
 UINT64 RequestStatus;
}QTB_VOTE_TABLE;
#pragma pack(pop)
STATIC_ASSERT(sizeof(QTB_VOTE_TABLE)==80,"OWQT packed receipt");
static EFI_STATUS QtbPublishVote(EFI_ACPI_TABLE_PROTOCOL *Acpi,BOOLEAN ExitedBootServices,UINTN *Key)
{
#if !OPEN_QTB_WITNESS
 (VOID)Acpi;(VOID)ExitedBootServices;(VOID)Key;return EFI_UNSUPPORTED;
#else
 static QTB_VOTE_TABLE T;
 if(ExitedBootServices||!Acpi||!Key||*Key||!mQtbTcuClient||!mQtbTcuReturned)return EFI_NOT_READY;
 ZeroMem(&T,sizeof(T));CopyMem(&T.Header.Signature,"OWQT",4);T.Header.Length=sizeof(T);T.Header.Revision=1;
 CopyMem(T.Header.OemId,"OPEN  ",6);CopyMem(&T.Header.OemTableId,"QTBTTCU ",8);T.Header.OemRevision=1;
 T.Version=1;T.Master=196;T.Type=4;T.Ib=1000000;T.FamilyInference=1;
 UINT8 Sum=0;for(UINTN I=0;I<sizeof(T);I++)Sum+=((UINT8*)&T)[I];T.Header.Checksum=(UINT8)(0-Sum);
 return Acpi->InstallAcpiTable(Acpi,&T,sizeof(T),Key);
#endif
}
