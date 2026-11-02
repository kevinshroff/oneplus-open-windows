/* SPDX-License-Identifier: GPL-2.0-only
 * One-boot diagnostic composition. Not a PCI host publisher or runtime driver.
 * Root reviews this complete artifact before including/loading it in firmware.
 */
#include <Uefi.h>
#include <PiDxe.h>
#include <Library/DxeServicesTableLib.h>
#include <Guid/EventGroup.h>
#include <Protocol/AcpiTable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/ArmLib.h>
#include <Library/TimerLib.h>
#include "g289_boot_votes.h"
#include "g289_rc0.h"
#include "g202_qmp.h"
#include "G401Publish.h"
extern G200_STATUS G200BindEfiClock(G200_CLOCK_API*,const G200_LEASE*);
extern G200_STATUS G200BindEfiGccIo(G200_GCC_IO*,const G200_LEASE*);
extern G202_STATUS G202BindRailProtocols(G202_RAIL_CALLER*);
/* Candidate-unit profile: raw type4 Ib800000/Ab500000. This corresponds to
 * OEM icc_set_bw(500,800) kB/s under the QTI/BCM byte-rate family inference.
 * No claim of exact NPA-source ABI equality with the 2026 ATF interface.
 * Fixed raw geometry is independently proven by frozen G222 instructions.
 */
#define G289_ICB_UNIT_INFERENCE_PROFILE 1u
#define MAGIC SIGNATURE_32('G','2','8','9')
#include "G289Report.h"
#include "g715_smmu_identity.h"

static REPORT*mR;static EFI_EVENT mReady,mExit;static UINT32 mOnce,mProtected;
static G200_CLOCK_CONTEXT mClock;static G200_CLOCK_API mClockApi;
static G200_GCC_IO mGcc;static G202_PINS mPins;static G202_QMP mQmp;
static G202_RAIL_CALLER mRails;static G289_NPA*mNpa;static void*mIcb,*mCorners[2];
static G200_LEASE mLease;
static const UINT64 Aon[24]={0x152020,0x152000,0x152008,0x16b000,0x16b004,0x16b008,
 0x16b01c,0x16b020,0x16b02c,0x16b038,0x16b03c,0x16b048,0x16b054,0x16c000,
 0x16c004,0x16c01c,0xf153000,0xf153004,0xf15e000,0xf15e004,0xf160000,0xf160004,0xf150000,0xf150004};
static UINT64 Now(void){return GetTimeInNanoSecond(GetPerformanceCounter())/1000;}
static void Refresh(void){mLease.NowUs=Now();mLease.ExpiresUs=mLease.NowUs+60000000;}
/* G310-r2: fixed-source device translation admission, before any MMIO.
 * GCC is the exact retained DT reg aperture rounded to pages; the EFI clock
 * provider may reach its internal PLL/vote/status registers. Other protected
 * pages cover only the fixed executor allowlist. Existing AOP/TLMM/doorbell
 * pages are checked through the same path. Mapping conveys no hardware lease.
 */
static EFI_STATUS PrepareMappings(void){
 static const struct{UINT64 Base,Length;} R[]={
  {0x100000,0x1f5000}, {0x1c00000,0x3000}, {0x1c06000,0x2000},
  {0x60000000,0x2000}, {0x60100000,0x100000},
  {0xf150000,0x1000}, {0xf153000,0x1000}, {0xf15e000,0x1000},
  {0xf160000,0x1000}, {0xc300000,0x1000}, {0x408000,0x1000},
  {0x1fd5000,0x1000} /* TCSR PCIe reference branch */
 };
 /* Validate the entire fixed set before adding mappings. Never reinterpret
  * RAM/reserved/more-reliable regions, owned IO or conflicting attributes.
  */
 for(UINTN Pass=0;Pass<2;Pass++)for(UINTN I=0;I<sizeof(R)/sizeof(R[0]);I++)
 for(UINT64 A=R[I].Base;A<R[I].Base+R[I].Length;A+=0x1000){
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR D;EFI_STATUS E=gDS->GetMemorySpaceDescriptor(A,&D);
  if(EFI_ERROR(E))return E;
  if(D.BaseAddress>A||D.Length<0x1000||A-D.BaseAddress>D.Length-0x1000)return EFI_NOT_READY;
  if(D.GcdMemoryType!=EfiGcdMemoryTypeNonExistent&&D.GcdMemoryType!=EfiGcdMemoryTypeMemoryMappedIo)return EFI_ACCESS_DENIED;
  if(D.ImageHandle||D.DeviceHandle)return EFI_ACCESS_DENIED;
  if(D.GcdMemoryType==EfiGcdMemoryTypeMemoryMappedIo&&
   (!(D.Capabilities&EFI_MEMORY_UC)||(D.Attributes&~(EFI_MEMORY_UC|EFI_MEMORY_XP))))return EFI_ACCESS_DENIED;
  if(!Pass)continue;
  if(D.GcdMemoryType==EfiGcdMemoryTypeNonExistent){
   E=gDS->AddMemorySpace(EfiGcdMemoryTypeMemoryMappedIo,A,0x1000,EFI_MEMORY_UC|EFI_MEMORY_XP);
   if(EFI_ERROR(E))return E;
  }
  /* UC is nonzero CPU-arch cache state. The GCD implementation calls the
   * platform CPU SetMemoryAttributes and propagates its failure; this is
   * deliberately called even if returned metadata already advertises UC.
   * Existing IO without XP capability preserves its supported attributes.
   */
  E=gDS->GetMemorySpaceDescriptor(A,&D);if(EFI_ERROR(E))return E;
  UINT64 Attributes=EFI_MEMORY_UC|((D.Capabilities&EFI_MEMORY_XP)?EFI_MEMORY_XP:0);
  E=gDS->SetMemorySpaceAttributes(A,0x1000,Attributes);if(EFI_ERROR(E))return E;
  E=gDS->GetMemorySpaceDescriptor(A,&D);if(EFI_ERROR(E))return E;
  if(D.GcdMemoryType!=EfiGcdMemoryTypeMemoryMappedIo||D.Attributes!=Attributes||
   D.BaseAddress>A||D.Length<0x1000||A-D.BaseAddress>D.Length-0x1000)return EFI_DEVICE_ERROR;
 }
 return EFI_SUCCESS;
}
static EFI_STATUS Samples(UINT32 S[2][24]){
 for(UINT32 N=0;N<2;N++)for(UINT32 I=0;I<24;I++){ArmDataMemoryBarrier();S[N][I]=MmioRead32((UINTN)Aon[I]);ArmDataMemoryBarrier();}
 return EFI_SUCCESS;
}
static int AonAllowed(UINT64 A){for(UINT32 I=0;I<24;I++)if(Aon[I]==A)return 1;return 0;}
static int ProtectedAddress(UINT64 A){return !(A&3)&&((A>=0x1c00000&&A<0x1c03000)||
 (A>=0x1c06000&&A<0x1c08000)||(A>=0x60000000&&A<0x6000101c)||(A>=0x60001200&&A<0x6000121c)||(A>=0x60001400&&A<0x6000141c)||
 (A>=0x60100000&&A<0x60200000)||(A>=0x15000000&&A<0x15010000));}
static G200_STATUS Read(void*O,uint64_t A,uint32_t*V){(VOID)O;if(!V||(!AonAllowed(A)&&!(mProtected&&ProtectedAddress(A))))return G200_INVALID;ArmDataMemoryBarrier();*V=MmioRead32((UINTN)A);ArmDataMemoryBarrier();return 0;}
static G200_STATUS Write(void*O,uint64_t A,uint32_t V){(VOID)O;if(!mProtected||!ProtectedAddress(A)||A>=0x60100000)return G200_INVALID;ArmDataMemoryBarrier();MmioWrite32((UINTN)A,V);ArmDataMemoryBarrier();return 0;}
static G200_STATUS Stall(void*O,uint32_t Us){(VOID)O;if(Us!=1000&&Us!=5000&&Us!=10000)return G200_INVALID;return gBS->Stall(Us);}
/* G324: explicit dynamic-provider registration before pin or rail mutation.
 * Exact patched PmicDxe TEST revision1+slot16 is a void/no-This one-shot
 * constructor, not EFI_STATUS. It registers all discovered scalar nodes,
 * skips existing names and retains definitions until reset. No direct PMIC
 * writes, Issue, Complete or private container pointers are supplied here.
 */
typedef struct {UINT64 AvailableEfi;UINT32 Available,Type;UINT64 QueryEfi;UINT32 QueryStatus,State;} REG_ROW;
typedef struct {UINT32 Magic,Version,Bytes,Stage;UINT64 Status,ProtocolRevision,LocateStatus;
 UINT32 Invoked,MissingBefore,MissingAfter,Selector;REG_ROW Before[13],After[13];} REG_REPORT;
_Static_assert(sizeof(REG_ROW)==32&&sizeof(REG_REPORT)==888,"G324 report ABI");
static REG_REPORT mReg;
static EFI_STATUS RegistrationScan(REG_ROW Rows[13],UINT32*Missing){
 *Missing=0;
 for(UINT32 I=0;I<13;I++){
  REG_ROW*R=&Rows[I];R->Available=UINT32_MAX;R->Type=UINT32_MAX;R->QueryStatus=UINT32_MAX;R->State=UINT32_MAX;
  R->QueryEfi=EFI_NOT_READY;
  R->AvailableEfi=mNpa->Available(G289Specs[I].Resource,&R->Available);
  if(R->AvailableEfi)return R->AvailableEfi;
  if(R->Available==2){*Missing|=1u<<I;continue;}
  if(R->Available)return EFI_DEVICE_ERROR;
  G289_QUERY Q={UINT32_MAX,0,{.Raw=UINT64_MAX}};
  R->QueryEfi=mNpa->Query(G289Specs[I].Resource,0,&Q,&R->QueryStatus);R->Type=Q.Type;R->State=Q.Data.State;
  if(R->QueryEfi)return R->QueryEfi;
  if(R->QueryStatus||R->Type)return EFI_DEVICE_ERROR;
 }
 return EFI_SUCCESS;
}
static EFI_STATUS EnsureRadioProvidersInner(void){
 mReg.Magic=SIGNATURE_32('G','3','2','4');mReg.Version=1;mReg.Bytes=sizeof(mReg);mReg.Stage=1;mReg.Selector=16;
 if(!mNpa||mNpa->Version!=0x10003||!mNpa->Available||!mNpa->Query)return EFI_UNSUPPORTED;
 EFI_STATUS E=RegistrationScan(mReg.Before,&mReg.MissingBefore);if(E)return E;
 if(!mReg.MissingBefore){CopyMem(mReg.After,mReg.Before,sizeof(mReg.After));mReg.Stage=4;return EFI_SUCCESS;}
 /* Only the five source dynamic SMPS pairs may need construction. Static
  * LDO/PAM absence or partial mV/en pair is a distinct failure, not repaired.
  * Generator tests /en before creating the three-resource scalar node.
  */
 if(mReg.MissingBefore&~0xffcu)return EFI_NOT_READY;
 for(UINT32 I=2;I<12;I+=2){UINT32 Pair=(mReg.MissingBefore>>I)&3;if(Pair&&Pair!=3)return EFI_NOT_READY;}
 struct {UINT64 Revision;VOID*Unused8;VOID(EFIAPI*RegisterDiscovered)(VOID);}*P=0;
 EFI_GUID Guid={0xec3aad30,0x1036,0x4767,{0xac,0x14,0xe6,0xf7,0xa6,0x9b,0xbe,0x1e}};
 mReg.Stage=2;E=gBS->LocateProtocol(&Guid,0,(VOID**)&P);mReg.LocateStatus=E;
 if(E)return E;if(!P)return EFI_UNSUPPORTED;mReg.ProtocolRevision=P->Revision;
 if(P->Revision!=1||!P->RegisterDiscovered)return EFI_UNSUPPORTED;
 mReg.Invoked=1;P->RegisterDiscovered(); /* may assert/hang internally; no invented status */
 mReg.Stage=3;E=RegistrationScan(mReg.After,&mReg.MissingAfter);if(E)return E;
 if(mReg.MissingAfter)return EFI_NOT_READY;
 mReg.Stage=4;return EFI_SUCCESS;
}
static EFI_STATUS EnsureRadioProviders(void){EFI_STATUS E=EnsureRadioProvidersInner();mReg.Status=E;return E;}
/* G336 records actual returned CmdDb addresses, without extra queries. */
/* G347 is explicitly awake-pinned, not a fabricated AOP-PDC receipt. */
static UINT32 mAwakeAdmitted;
static EFI_STATUS AdmitAwakeProfile(void){
 const UINT32 All=(1u<<13)-1;
 if(mLease.PowerProfile!=G200_POWER_AWAKE_PINNED||
  (mLease.Witnesses&G200_W_AOP_PDC)||mR->Votes.ReturnedMask!=All||
  mR->Votes.ObservedMask!=All||mR->CornerMask!=3||!mRails.Client||
  !mRails.Trace[6].Attempted||mRails.Trace[6].Status||mR->XoRequestId==UINT32_MAX)return EFI_NOT_READY;
 for(UINT32 I=0;I<13;I++)if(mR->Votes.CachedAfter[I]<G289Specs[I].Request)return EFI_NOT_READY;
 mLease.Witnesses|=G200_W_AWAKE_PINNED;mAwakeAdmitted=1;return EFI_SUCCESS;
}
static void PublishAwakeProfile(EFI_ACPI_TABLE_PROTOCOL*A){
 struct {UINT32 Magic,Version,Bytes,Profile,AopAttempted,PdcFrames,RequireAwake,NoSleepClaim;
  UINT32 VotesObserved,CornerMask,XoReturned,RetainUntilReset;UINT64 Witnesses;
  UINT32 ZeroAopWitness,Admitted;}P={0};
 _Static_assert(sizeof(P)==64,"G347 profile report ABI");
 P.Magic=SIGNATURE_32('G','3','4','7');P.Version=1;P.Bytes=sizeof(P);P.Profile=mLease.PowerProfile;
 P.PdcFrames=mR->PdcFrames;P.RequireAwake=1;P.NoSleepClaim=1;P.VotesObserved=mR->Votes.ObservedMask;
 P.CornerMask=mR->CornerMask;P.XoReturned=(mLease.Witnesses&G200_W_REFERENCE)!=0;
 P.RetainUntilReset=1;P.Witnesses=mLease.Witnesses;
 P.ZeroAopWitness=(mLease.Witnesses&G200_W_AOP_PDC)==0;P.Admitted=mAwakeAdmitted;
 UINT8 B[36+sizeof(P)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','A','P');H.Length=sizeof(B);H.Revision=2;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G347AWAK",8);H.OemRevision=347;
 H.Creator=SIGNATURE_32('G','3','4','7');H.CreatorRevision=1;
 CopyMem(B,&H,36);CopyMem(B+36,&P,sizeof(P));UINT8 Sum=0;for(UINTN I=0;I<sizeof(B);I++)Sum+=B[I];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
static void PublishClockDiscovery(EFI_ACPI_TABLE_PROTOCOL*A){
 struct {UINT32 Magic,Version,Index,Operation,Hz,PriorEnabled;UINT64 Status;
  UINT32 PriorOn,HardwareRateAdmitted;UINT64 RateStatus;UINT32 RateWords[2][10],InitialRateWords[10];}P={0};
 _Static_assert(sizeof(P)==168,"G371 clock admission ABI3");
 P.Magic=SIGNATURE_32('G','3','7','1');P.Version=3;P.Index=mClock.DiscoverIndex;
 P.Operation=mClock.DiscoverOp;P.Hz=mClock.DiscoverHz;P.PriorEnabled=mClock.DiscoverEnabled;
 P.Status=mClock.DiscoverStatus;P.PriorOn=mClock.DiscoverOn;
 P.HardwareRateAdmitted=mClock.HardwareRateAdmitted;P.RateStatus=mClock.RateStatus;
 CopyMem(P.RateWords,mClock.RateWords,sizeof(P.RateWords));
 CopyMem(P.InitialRateWords,mClock.InitialRateWords,sizeof(P.InitialRateWords));
 UINT8 B[36+sizeof(P)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','C','K');H.Length=sizeof(B);H.Revision=3;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G371CLK ",8);H.OemRevision=371;
 H.Creator=SIGNATURE_32('G','3','7','1');H.CreatorRevision=3;
 CopyMem(B,&H,36);CopyMem(B+36,&P,sizeof(P));UINT8 Sum=0;for(UINTN I=0;I<sizeof(B);I++)Sum+=B[I];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
static void PublishPipe(EFI_ACPI_TABLE_PROTOCOL*A){
 UINT8 B[36+sizeof(mClock.Pipe)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','P','I');H.Length=sizeof(B);H.Revision=2;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G396PIPE",8);H.OemRevision=396;
 H.Creator=SIGNATURE_32('G','3','9','6');H.CreatorRevision=1;
 CopyMem(B,&H,36);CopyMem(B+36,&mClock.Pipe,sizeof(mClock.Pipe));
 UINT8 Sum=0;for(UINTN J=0;J<sizeof(B);J++)Sum+=B[J];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
static void PublishCmdDb(EFI_ACPI_TABLE_PROTOCOL*A){
 UINT8 B[36+16+sizeof(mRails.Trace)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','C','D');H.Length=sizeof(B);H.Revision=2;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G336CMDB",8);H.OemRevision=336;
 H.Creator=SIGNATURE_32('G','3','3','6');H.CreatorRevision=1;
 UINT32 P[4]={SIGNATURE_32('G','3','3','6'),1,16+sizeof(mRails.Trace),16};
 CopyMem(B,&H,36);CopyMem(B+36,P,sizeof(P));CopyMem(B+52,mRails.Trace,sizeof(mRails.Trace));
 UINT8 Sum=0;for(UINTN I=0;I<sizeof(B);I++)Sum+=B[I];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
static void PublishRegistration(EFI_ACPI_TABLE_PROTOCOL*A){
 UINT8 B[36+sizeof(mReg)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','R','G');H.Length=sizeof(B);H.Revision=2;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G324REG ",8);H.OemRevision=324;
 H.Creator=SIGNATURE_32('G','3','2','4');H.CreatorRevision=1;
 CopyMem(B,&H,36);CopyMem(B+36,&mReg,sizeof(mReg));UINT8 Sum=0;for(UINTN I=0;I<sizeof(B);I++)Sum+=B[I];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
static G401_REPORT mTransport;static G403_RESULT mSid;static G401_PUBLICATION_REPORT mPublication;
static EFI_STATUS mTransportIoStatus,mGateStatus;
static int LiveGate(void*Unused){
 (VOID)Unused;Refresh();UINT32 S[2][24];EFI_STATUS E=Samples(S);
 if(!E)E=G200ActiveReady(&mClock,&mLease,(const uint32_t(*)[24])S);
 UINT32 Mux=UINT32_MAX,Id=0,Command=UINT32_MAX,Link=0,Elbi=0;
 if(!E)E=mGcc.Read32(mGcc.Opaque,0x16b070,&Mux);
 if(!E&&((Mux&3U)||(S[0][11]&0x80000000U)))E=EFI_NOT_READY;
 UINT8 V=2;
 if(!E){E=mClockApi.IsOn(mClockApi.This,mClock.R[G200_PIPE].Id,&V);if(!E&&V!=1)E=EFI_NOT_READY;}
 V=2;if(!E){E=mClockApi.IsEnabled(mClockApi.This,mClock.R[G200_PIPE].Id,&V);if(!E&&V!=1)E=EFI_NOT_READY;}
 if(!E)E=Read(0,0x60000080,&Link);if(!E)E=Read(0,0x60000f28,&Elbi);
 if(!E)E=Read(0,0x60100000,&Id);if(!E)E=Read(0,0x60100004,&Command);
 if(!E&&(!mR->Rc.IdentityValid||Id!=0x110717cb||(Command&4)||!(Link&(1U<<29))||!(Elbi&0x400)))E=EFI_NOT_READY;
 mGateStatus=E;return EFI_ERROR(E)?1:0;
}
static int TransportRead(void*O,uint64_t A,uint32_t*V){
 (VOID)O;mTransportIoStatus=Read(0,A,V);return EFI_ERROR(mTransportIoStatus)?1:0;
}
static int TransportWrite(void*O,uint64_t A,uint32_t V){
 (VOID)O;
 if(!(A==0x60000004||A==0x60000018||A==0x60000020||(A>=0x60001000&&A<=0x60001018)||(A>=0x60001200&&A<=0x60001218)||(A>=0x60001400&&A<=0x60001418)||
      (A>=0x1c02000&&A<0x1c02400)||A==0x1c02c00))return 1;
 mTransportIoStatus=Write(0,A,V);return EFI_ERROR(mTransportIoStatus)?1:0;
}
static int TransportWait(void*O,uint32_t Us){(VOID)O;return Us==1000&&gBS->Stall(Us)==EFI_SUCCESS?0:1;}
static EFI_STATUS PrepareTransport(void){
 if(LiveGate(0))return mGateStatus;
 G401_IOPS Io={0,TransportRead,TransportWrite,TransportWait};int E=G401PrepareBus1Ecam(&mTransport,&Io);
 return !E?EFI_SUCCESS:E==G401_UNSUPPORTED?EFI_UNSUPPORTED:E==G401_NOT_READY?EFI_NOT_READY:EFI_DEVICE_ERROR;
}
static int SidColdGate(void*Unused){
 /* This is the reset-only, pre-publication coordinator, never an OS/live-table
  * maintenance entry. Reprove actual local reset history and fresh LiveGate.
  */
 if(!mClock.ResetsCycled||!G200LeaseHas(&mLease,G200_W_COLD_SELECTED|G200_W_RESETS_CYCLED|G200_W_NO_PCI_CONSUMER)||
    mTransport.Stage!=6||mTransport.FirstError||!mTransport.SeparationValid||!mTransport.MemValid||
    !mTransport.RootForwardingValid||mPublication.Attempted||mPublication.RootPublished)return 1;
 return LiveGate(Unused);
}
static EFI_STATUS PrepareSid(void){
 G403_IO Io={0,TransportRead,TransportWrite};return G403PrepareSid(&Io,SidColdGate,0,&mSid)?EFI_DEVICE_ERROR:EFI_SUCCESS;
}
static G715_RESULT mIdentity;
static int SmmuMapTolerant(UINT64 Page){
 /* Best-effort UC mapping for one SMMU page; existing mappings (any MMIO
  * attributes) are accepted as-is, only NonExistent space is added. */
 EFI_GCD_MEMORY_SPACE_DESCRIPTOR D;
 EFI_STATUS E=gDS->GetMemorySpaceDescriptor(Page,&D);
 if(EFI_ERROR(E))return 1;
 if(D.GcdMemoryType==EfiGcdMemoryTypeMemoryMappedIo)return 0;
 if(D.GcdMemoryType!=EfiGcdMemoryTypeNonExistent)return 1;
 E=gDS->AddMemorySpace(EfiGcdMemoryTypeMemoryMappedIo,Page,0x1000,EFI_MEMORY_UC|EFI_MEMORY_XP);
 return EFI_ERROR(E)?1:0;
}
static int SmmuRead(void*O,uint64_t A,uint32_t*V){(VOID)O;return EFI_ERROR(Read(0,A,V))?1:0;}
static int SmmuWrite(void*O,uint64_t A,uint32_t V){(VOID)O;return EFI_ERROR(Write(0,A,V))?1:0;}
static EFI_STATUS PrepareSmmuIdentity(void){
 /* G715: the tagged PCIe0 streams (root 0x1400, WLAN 0x1401) have no
  * Windows-side SMMU owner; unmatched streams fault fatally on the first
  * device DMA. Give both streams identity pass-through context banks while
  * PARF SID translation stays enabled, before the namespace publishes.
  * Best-effort: a failure here is recorded in mIdentity and MUST NOT abort
  * the driver's publication; the result is observable through the trace. */
 G403_IO Io={0,SmmuRead,SmmuWrite};
 for(UINT64 A=UINT64_C(0x15000000);A<UINT64_C(0x15010000);A+=0x1000)SmmuMapTolerant(A);
 if(G715PrepareIdentity(&Io,&mIdentity)){
  /* Fallback: identity banks unavailable -> re-assert PARF SID bypass so
   * device traffic keeps raw RIDs (the pre-G403 stock state) instead of
   * hitting unmatched translated streams. */
  UINT32 Cfg;
  if(!SmmuRead(0,UINT64_C(0x1c02c00),&Cfg)&&!(Cfg&1u))(VOID)SmmuWrite(0,UINT64_C(0x1c02c00),Cfg|1u);
  mIdentity.Fallback=1;
 }
 return EFI_SUCCESS;
}
static void PublishTransport(EFI_ACPI_TABLE_PROTOCOL*A){
 G401_FLOW_REPORT P;
 ZeroMem(&P,sizeof(P));P.Magic=SIGNATURE_32('G','4','2','3');P.Version=2;P.Bytes=sizeof(P);
 P.Transport=mTransport;P.Sid=mSid;P.Publication=mPublication;
 P.GateStatus=mGateStatus;P.IoStatus=mTransportIoStatus;
 UINT8 B[36+sizeof(P)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','T','R');H.Length=sizeof(B);H.Revision=2;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G423PCI ",8);H.OemRevision=423;
 H.Creator=SIGNATURE_32('G','4','2','3');H.CreatorRevision=2;
 CopyMem(B,&H,36);CopyMem(B+36,&P,sizeof(P));UINT8 Sum=0;
 for(UINTN J=0;J<sizeof(B);J++)Sum+=B[J];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
static EFI_STATUS KeepCorner(UINT32 I){
 static const char*Names[2]={"/vcs/vdd_cx","/vcs/vdd_mx"};
 static const char*Clients[2]={"Open289-cx","Open289-mx"};UINT32 A=UINT32_MAX;
 EFI_STATUS E=mNpa->Available(Names[I],&A);if(E||A)return E?E:EFI_NOT_READY;
 E=mNpa->Create(Names[I],Clients[I],0x40,0,0,&mCorners[I]);if(E||!mCorners[I])return E?E:EFI_DEVICE_ERROR;
 E=mNpa->Request(mCorners[I],256);if(!E)mR->CornerMask|=1u<<I;return E;
}
static EFI_STATUS KeepIcb(void){
 _Alignas(8) static const UINT32 Pairs[4]={65,0,0,88}; /*actual frozen DMA and APSS-config paths*/
 _Alignas(8) static const UINT32 Request[16]={4,0,800000,0,500000,0,0,0,4,0,800000,0,500000,0,0,0};
 UINT32 A=UINT32_MAX;EFI_STATUS E=mNpa->Available("/icb/arbiter",&A);if(E||A)return E?E:EFI_NOT_READY;
 E=mNpa->Create("/icb/arbiter","Open289-rc0",0x400,sizeof(Pairs),(void*)Pairs,&mIcb);
 if(E||!mIcb)return E?E:EFI_DEVICE_ERROR;
 /* Exact NPA vector+144, length measured in uint32 words, never bytes. */
 typedef EFI_STATUS(*VECTOR)(void*,UINT32,const UINT32*);
 VECTOR V=*(VECTOR*)((UINT8*)mNpa+144);if(!V)return EFI_UNSUPPORTED;
 mR->IcbAttempted=1;E=V(mIcb,16,Request);if(!E)mR->IcbReturned=1;return E;
}
/* Final inline snapshot is available through ordinary Windows ACPI table
 * APIs (OWIR), so native inspection needs no physical-memory reader. OWIF
 * additionally preserves the live NVS pointer for an interrupted operation.
 * ExitedBootServices in this earlier copy is necessarily0, not a certificate.
 */
static void PublishFinal(void){
 EFI_ACPI_TABLE_PROTOCOL*A=0;EFI_STATUS E=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,0,(VOID**)&A);if(EFI_ERROR(E))return;
 PublishRegistration(A);
 PublishCmdDb(A);
 PublishAwakeProfile(A);
 PublishClockDiscovery(A);
 PublishPipe(A);
 PublishTransport(A);
 UINT8 B[36+sizeof(REPORT)];ZeroMem(B,sizeof(B));TABLE H={0};
 H.Signature=SIGNATURE_32('O','W','I','R');H.Length=sizeof(B);H.Revision=2;
 CopyMem(H.Oem,"OPEN  ",6);CopyMem(H.OemId,"G289WLAN",8);H.OemRevision=289;H.Creator=MAGIC;H.CreatorRevision=1;
 CopyMem(B,&H,36);CopyMem(B+36,mR,sizeof(*mR));UINT8 Sum=0;for(UINTN I=0;I<sizeof(B);I++)Sum+=B[I];B[9]=(UINT8)(0-Sum);
 UINTN Key=0;(VOID)A->InstallAcpiTable(A,B,sizeof(B),&Key);
}
#define STEP(N,X) do{mR->Stage=(N);EFI_STATUS e=(X);if(EFI_ERROR(e)){mR->Status=e;goto Done;}}while(0)
static VOID EFIAPI Ready(EFI_EVENT Event,VOID*Context){
 (VOID)Event;(VOID)Context;if(mOnce++)return;mR->Attempted=1;mR->RetainedUntilReset=1;
 mLease=(G200_LEASE){1,289,0,0,0,1,1,1,G200_POWER_AWAKE_PINNED};Refresh();
 STEP(28,PrepareMappings());
 STEP(1,Samples(mR->Initial));
 /* Current selector/pin/cold-domain observations; never read RC while off. */
 for(UINT32 I=0;I<24;I++)if(mR->Initial[0][I]!=mR->Initial[1][I]){mR->Status=EFI_NOT_READY;goto Done;}
 if((mR->Initial[0][16]&0x123c)||(mR->Initial[0][17]&1)||
 (mR->Initial[0][4]&0x80000000)||(mR->Initial[0][13]&0x80000000)){
  mR->Status=EFI_NOT_READY;goto Done;
 }
 mLease.Witnesses=G200_W_COLD_SELECTED|G200_W_NO_PCI_CONSUMER;
 STEP(2,G289BindNpa(&mNpa));
 STEP(29,EnsureRadioProviders());
 STEP(3,G202BindEfiPins(&mPins));STEP(4,G202PinPrepare(&mPins));
 mLease.Witnesses|=G200_W_PERST_ASSERTED;
 Refresh();STEP(5,G289BootVote(&mR->Votes,mNpa,&mLease));
 mLease.Witnesses|=G200_W_RADIO_SIX_RAILS|G200_W_ROOT_RAILS;
 STEP(6,KeepCorner(0));STEP(7,KeepCorner(1));mLease.Witnesses|=G200_W_PARENT_CX_MX;
 STEP(8,G202BindRailProtocols(&mRails));STEP(9,G202ResolveRailAddresses(&mRails));
 STEP(10,G202CreateRailClient(&mRails));STEP(11,G202IssueXoReference(&mRails,&mR->XoAddress,&mR->XoRequestId));
 mLease.Witnesses|=G200_W_REFERENCE;
 /* Exact Open CNSS makes QMP/PDC setup optional at probe. This selected
  * first-awake profile retains all active votes and omits sleep/PDC policy.
  * No raw QMP read/write, GLINK open, pending-mailbox clear or fake PDC bit.
  */
 STEP(30,AdmitAwakeProfile());
 STEP(16,G202PinActivate(&mPins));mLease.Witnesses|=G200_W_WLAN_EN;
 Refresh();STEP(17,G200BindEfiClock(&mClockApi,&mLease));STEP(18,G200BindEfiGccIo(&mGcc,&mLease));
 STEP(19,G200ClockOpen(&mClock,&mClockApi,&mLease));
 /* ICC is requested before all clock changes, satisfying G200's stricter
  * prerequisite. OEM requests it after domains/mux, before non-PIPE clocks. */
 STEP(20,KeepIcb());mLease.Witnesses|=G200_W_INTERCONNECT;
 for(UINT32 I=0;I<11;I++){
  Refresh();STEP(21,G200ClockNext(&mClock,&mLease));
  if(mClock.Next==2){STEP(22,G200GccMuxExternal(&mClock,&mLease,&mGcc));mLease.Witnesses|=G200_W_PIPE_MUX;}
 }
 Refresh();STEP(23,G200GccResetPair(&mClock,&mLease,&mGcc));mLease.Witnesses|=G200_W_RESETS_CYCLED;
 STEP(24,Samples(mR->BeforeRc));Refresh();STEP(25,G200AccessReady(&mClock,&mLease,(const uint32_t(*)[24])mR->BeforeRc,0));
 mProtected=mR->Protected=1;
 G200_GCC_IO Io={0,Read,Write,Stall};STEP(26,G289RcIdentity(&mR->Rc,&mClock,&mLease,&mPins,&Io,&mGcc,(const uint32_t(*)[24])mR->BeforeRc));
 STEP(40,G401PreparePublication(&mPublication));
 STEP(41,PrepareTransport());STEP(42,PrepareSid());
 STEP(43,PrepareSmmuIdentity());
 STEP(44,G401PublishRoot(&mTransport,TRUE,LiveGate,0,&mPublication));
 mLease.Witnesses&=~G200_W_NO_PCI_CONSUMER; /* namespace published; firmware ownership gate closes */
 mR->Stage=27;mR->Status=EFI_SUCCESS;
 Done:
 mR->ClockNext=mClock.Next;mR->ClockFault=mClock.Fault;mR->ClockUncertain=mClock.UncertainMask;
 mR->ClockFirst=mClock.FirstStatus;mR->PinFirst=mPins.FirstError;mR->QmpFirst=mQmp.FirstError;
 PublishFinal();
 /* No hardware unwind/retry. Conditional PCI namespace is published only
  * after transport, platform-table and same-boot physical gates succeed. */
}
static VOID EFIAPI Exit(EFI_EVENT Event,VOID*Context){(VOID)Event;(VOID)Context;if(mR)mR->ExitedBootServices=1;mProtected=0;mLease.BootServicesActive=0;}
EFI_STATUS EFIAPI G289DriverEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE*System){
 (VOID)Image;(VOID)System;EFI_STATUS E;EFI_PHYSICAL_ADDRESS A=0;EFI_ACPI_TABLE_PROTOCOL*Acpi=0;
 E=gBS->AllocatePages(AllocateAnyPages,EfiACPIMemoryNVS,EFI_SIZE_TO_PAGES(sizeof(REPORT)),&A);if(EFI_ERROR(E))return E;
 mReg.Magic=SIGNATURE_32('G','3','2','4');mReg.Version=1;mReg.Bytes=sizeof(mReg);mReg.Status=EFI_NOT_READY;mReg.Selector=16;
 mR=(REPORT*)(UINTN)A;ZeroMem(mR,sizeof(*mR));mR->Magic=MAGIC;mR->Version=1;mR->Bytes=sizeof(*mR);mR->Status=EFI_NOT_READY;mR->IcbProfile=G289_ICB_UNIT_INFERENCE_PROFILE;
 E=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,0,(VOID**)&Acpi);if(EFI_ERROR(E))return EFI_SUCCESS;
 TABLE T={0};T.Signature=SIGNATURE_32('O','W','I','F');T.Length=sizeof(T);T.Revision=1;
 CopyMem(T.Oem,"OPEN  ",6);CopyMem(T.OemId,"G289WLAN",8);T.OemRevision=289;T.Creator=MAGIC;T.CreatorRevision=1;
 T.Address=A;T.Bytes=sizeof(*mR);T.Abi=1;UINT8 Sum=0;for(UINTN I=0;I<sizeof(T);I++)Sum+=((UINT8*)&T)[I];T.Checksum=(UINT8)(0-Sum);
 UINTN Key=0;E=Acpi->InstallAcpiTable(Acpi,&T,sizeof(T),&Key);if(EFI_ERROR(E)){mR->Status=E;return EFI_SUCCESS;}
 E=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,Exit,0,&gEfiEventExitBootServicesGuid,&mExit);if(EFI_ERROR(E)){mR->Status=E;return EFI_SUCCESS;}
 E=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,Ready,0,&gEfiEventReadyToBootGuid,&mReady);if(EFI_ERROR(E))mR->Status=E;
 return EFI_SUCCESS;
}
