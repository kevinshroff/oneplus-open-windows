#include "G530Lease.h"
/* SPDX-License-Identifier: MIT
 * Private awake-only pre-EBS power owner. Fixed Open source addresses only.
 * Source proposal: root must integrate/order this selected prototype. No
 * NPA/clock calls after EBS. Retain every created vote until full-reset recovery.
 */
#include <Uefi.h>
#include <PiDxe.h>
#include <Protocol/AcpiTable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/IoLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/TimerLib.h>
#include <Library/DebugLib.h>
#include "g290_power_report.h"
#include "g323_clock_policy.h"
#include "g335_cx_context.h"
#include <Protocol/EFIClock.h>
#include "g335_hub_report.h"
#include "g366_external_report.h"
typedef struct {UINT32 Type,Pad;union {UINT32 State;UINT64 Raw;}Data;} G290_QUERY;
typedef struct {
    UINT64 Version,Unused8;
    EFI_STATUS (*Create)(CONST CHAR8*,CONST CHAR8*,UINT32,UINT32,VOID*,VOID**);
    UINT64 Unused24,Unused32;EFI_STATUS (*Request)(VOID*,UINT32);
    UINT64 Unused48Through104[8];EFI_STATUS (*Available)(CONST CHAR8*,UINT32*);
    UINT64 Unused120Through168[7];EFI_STATUS (*Query)(CONST CHAR8*,UINT32,G290_QUERY*,UINT32*);
} G290_NPA;
STATIC_ASSERT(OFFSET_OF(G290_NPA,Create)==16,"Create ABI");
STATIC_ASSERT(OFFSET_OF(G290_NPA,Request)==40,"Request ABI");
STATIC_ASSERT(OFFSET_OF(G290_NPA,Available)==112,"Available ABI");
STATIC_ASSERT(OFFSET_OF(G290_NPA,Query)==176,"Query ABI");
static EFI_GUID mNpaGuid={0x79d6c870,0x725e,0x489e,{0xa0,0xa1,0x27,0xe7,0xa5,0xd0,0xcb,0x35}};
/* Fixed context addresses share the already admitted0x03d99000 page. */
static G335_CX_CONTEXT mContext;
static G335_HUB_REPORT mHub;
static G366_EXTERNAL_REPORT mExternal;
STATIC_ASSERT(sizeof(G366_EXTERNAL_REPORT)==132,"OGEV ABI");
static EFI_STATUS ExternalParentLease(VOID)
{
    EFI_CLOCK_PROTOCOL *clock=NULL;EFI_GUID guid=EFI_CLOCK_PROTOCOL_GUID;
    UINTN id=MAX_UINTN;BOOLEAN enabled=0xa5;EFI_STATUS st;
    mExternal.Stage=1;
    mExternal.VoteBefore=MmioRead32(0x00152000);
    mExternal.BcrBefore=MmioRead32(0x00171000);
    if(mExternal.VoteBefore==MAX_UINT32||mExternal.BcrBefore==MAX_UINT32) {st=EFI_DEVICE_ERROR;goto done;}
    /* Observe only; an asserted upstream GPU reset is never repaired here. */
    if(mExternal.BcrBefore&1) {st=EFI_ACCESS_DENIED;goto done;}
    mExternal.Stage=2;st=gBS->LocateProtocol(&guid,NULL,(VOID**)&clock);
    if(EFI_ERROR(st)) goto done;
    if(!clock) {st=EFI_UNSUPPORTED;goto done;}
    mExternal.ProtocolVersion=clock->Version;
    if(clock->Version!=0x1000a||!clock->GetClockID||!clock->EnableClock||!clock->IsClockEnabled) {st=EFI_UNSUPPORTED;goto done;}
    mExternal.Stage=3;st=clock->GetClockID(clock,"gcc_gpu_gpll0_clk_src",&id);
    mExternal.GetIdStatus=st;mExternal.ClockId=id;
    if(EFI_ERROR(st)) goto done;
    if(id!=0x10096) {st=EFI_DEVICE_ERROR;goto done;}
    /* Linux CCF owns this externalparent even if another consumer is on.
     * No rate request, PLL programming input or direct APvote store here. */
    mExternal.Stage=4;mExternal.RetainedEnable=1;
    st=clock->EnableClock(clock,id);mExternal.EnableStatus=st;if(EFI_ERROR(st)) goto done;
    mExternal.Stage=5;st=clock->IsClockEnabled(clock,id,&enabled);
    mExternal.QueryStatus=st;mExternal.Enabled=enabled;
    if(EFI_ERROR(st)) goto done;
    if(enabled!=TRUE) {st=EFI_DEVICE_ERROR;goto done;}
    st=EFI_SUCCESS;
done:
    mExternal.VoteAfter=MmioRead32(0x00152000);
    mExternal.BcrAfter=MmioRead32(0x00171000);
    if(st==EFI_SUCCESS) {
        if(mExternal.VoteAfter==MAX_UINT32||mExternal.BcrAfter==MAX_UINT32||
           !(mExternal.VoteAfter&0x8000u)||(mExternal.BcrAfter&1)) st=EFI_DEVICE_ERROR;
        else mExternal.Stage=6;
    }
    mExternal.Status=st;return st;
}


#include "g400_gpll0_policy.h"
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT32 Flags,Polls;UINT64 Pa[6];
 UINT32 Before[2][6],Recheck[2][6],After[2][6];
 UINT32 VoteWriteBefore,VoteExpected,VoteReadback;
} G400_PLL_REPORT;
#pragma pack(pop)
static G400_PLL_REPORT mPll;
STATIC_ASSERT(sizeof(G400_PLL_REPORT)==264,"OGPL ABI");
static CONST UINTN mPllPa[6]={0x00100000,0x00100004,0x00100010,
 0x00100014,0x00100018,0x00152018};
static VOID PllSnapshot(UINT32 w[2][6])
{
 for(UINTN n=0;n<2;n++) for(UINTN j=0;j<6;j++) {
  MemoryFence();w[n][j]=MmioRead32(mPllPa[j]);MemoryFence();
 }
}
static EFI_STATUS GpllPreflight(VOID)
{
 EFI_STATUS st=EFI_NOT_READY;mPll.Stage=1;
 /* The official external route bundles XO retention and AP15. Admit it
  * only while AHB is disabled and its physical PLL ancestor is already on.
  * No cold PLL start, parent rate change or shared programming is allowed. */
 UINT32 ahb=MmioRead32(0x03d9911c);
 if(ahb==MAX_UINT32||(ahb&1u)) {st=EFI_ACCESS_DENIED;goto done;}
 PllSnapshot(mPll.Before);
 if(!G400PllStable600((CONST uint32_t(*)[6])mPll.Before)) goto done;
 mPll.Stage=2;st=EFI_SUCCESS;
done:mPll.Status=st;return st;
}
static EFI_STATUS GpllVote(VOID)
{
 EFI_STATUS st=EFI_NOT_READY;EFI_TPL tpl;UINT32 v,w;
 mPll.Stage=3;
 /* Existing supported external Enable has retained /pmic/client/xo before
  * this manual GPLL0 vote. It does NOT acquire GPLL0 in the actual BSP. */
 if(mExternal.Stage!=6||mExternal.Status!=EFI_SUCCESS||!mExternal.RetainedEnable) goto done;
 mPll.Flags|=8u;PllSnapshot(mPll.Recheck);
 if(!G400PllStable600((CONST uint32_t(*)[6])mPll.Recheck)) goto done;
 for(UINTN j=0;j<6;j++) if(mPll.Recheck[1][j]!=mPll.Before[1][j]) {
  mPll.Flags|=j==5?16u:32u;goto done;
 }
 v=MmioRead32(0x03d9911c);
 if(v==MAX_UINT32||(v&1u)) {st=EFI_ACCESS_DENIED;goto done;}
 mPll.Stage=4;
 /* Serialize this BSP's notify callbacks across only the short APvote RMW.
  * This does not claim atomic exclusion of other processors/secure agents.
  * Reject a changed captured word; do not clear or roll back shared bits. */
 tpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 v=MmioRead32(0x00152018);MemoryFence();w=MmioRead32(0x00152018);
 mPll.VoteWriteBefore=w;mPll.VoteExpected=w|1u;
 if(v!=w||w!=mPll.Recheck[1][5]||w==MAX_UINT32) {
  mPll.Flags|=16u;gBS->RestoreTPL(tpl);goto done;
 }
 mPll.Flags|=4u; /* retained until full reset; not a DAL refcount */
 if(!(w&1u)) {mPll.Flags|=1u;MmioWrite32(0x00152018,w|1u);MemoryFence();}
 else mPll.Flags|=2u;
 mPll.VoteReadback=MmioRead32(0x00152018);MemoryFence();
 gBS->RestoreTPL(tpl);
 if(mPll.VoteReadback!=(w|1u)) {mPll.Flags|=16u;st=EFI_DEVICE_ERROR;goto done;}
 mPll.Stage=5;st=EFI_TIMEOUT;
 /* Exact fixedLucidEVO voted branch polls MODE.LOCK, source bound100us.
  * USER25 was qualified; no OPMODE, L/ALPHA, USER, reset or PLL store. */
 for(UINTN n=0;n<100;n++) {
  v=MmioRead32(0x00100000);mPll.Polls++;
  if(v==MAX_UINT32) {st=EFI_DEVICE_ERROR;break;}
  if(v&0x80000000u) {st=EFI_SUCCESS;break;}
  MicroSecondDelay(1);
 }
 PllSnapshot(mPll.After);
 if(EFI_ERROR(st)) goto done;
 if(!G400PllStable600((CONST uint32_t(*)[6])mPll.After)) {st=EFI_DEVICE_ERROR;goto done;}
 for(UINTN j=0;j<5;j++) if(mPll.After[1][j]!=mPll.Before[1][j]) {
  mPll.Flags|=32u;st=EFI_DEVICE_ERROR;goto done;
 }
 if(mPll.After[1][5]!=(mPll.Before[1][5]|1u)) {mPll.Flags|=16u;st=EFI_DEVICE_ERROR;goto done;}
 mPll.Stage=6;
done:mPll.Status=st;return st;
}

STATIC_ASSERT(sizeof(G335_HUB_REPORT)==140,"OGHU ABI");
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,GetClockID)==8,"Clock ABI GetID");
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,EnableClock)==16,"Clock ABI Enable");
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,IsClockEnabled)==32,"Clock ABI Enabled");
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,SetClockFreqHz)==48,"Clock ABI SetHz");
static EFI_STATUS HubThroughProvider(VOID)
{
    EFI_GUID guid=EFI_CLOCK_PROTOCOL_GUID;EFI_CLOCK_PROTOCOL *clock=NULL;
    UINTN id=MAX_UINTN;UINT32 actual=MAX_UINT32;BOOLEAN enabled=0xa5;EFI_STATUS st;
    mHub.Stage=1;st=gBS->LocateProtocol(&guid,NULL,(VOID**)&clock);
    if((st!=EFI_SUCCESS)) goto done;
    if(!clock) {st=EFI_UNSUPPORTED;goto done;}
    mHub.ProtocolVersion=clock->Version;
    if(clock->Version!=0x1000a||!clock->GetClockID||!clock->SetClockFreqHz||
       !clock->EnableClock||!clock->IsClockEnabled) {st=EFI_UNSUPPORTED;goto done;}
    mHub.Stage=2;st=G530Bind(clock,&id);
    mHub.GetIdStatus=st;mHub.ClockId=id;
    if((st!=EFI_SUCCESS)) goto done;
    if(id!=0x1014a) {st=EFI_DEVICE_ERROR;goto done;}
    /* Exact Open A740 gmu_hub_clk_freq:200MHz. Set before enable so the
     * actual provider can configure/enable parents with its own refcounts. */
    mHub.Stage=3;st=clock->SetClockFreqHz(clock,id,200000000,
                                         EFI_CLOCK_FREQUENCY_HZ_EXACT,&actual);
    mHub.SetHzStatus=st;mHub.ReturnedHz=actual;
    if((st!=EFI_SUCCESS)) goto done;
    if(actual!=200000000) {st=EFI_DEVICE_ERROR;goto done;}
    st=G530Before(clock);if(st!=EFI_SUCCESS)goto done;
    mHub.Stage=4;mHub.RetainedEnable=1; /* retain even partial/failed calls */
    st=clock->EnableClock(clock,id);mHub.EnableStatus=st;
    st=G530After(clock,st);if(st!=EFI_SUCCESS)goto done;
    mHub.Stage=5;st=clock->IsClockEnabled(clock,id,&enabled);
    mHub.QueryStatus=st;mHub.Enabled=enabled;
    if((st!=EFI_SUCCESS)) goto done;
    /* Known false is the state the following direct branch step must enable.
     * Unknown/nonboolean output is never accepted as a disabled clock. */
    if(enabled!=FALSE&&enabled!=TRUE) {st=EFI_DEVICE_ERROR;goto done;}
    st=EFI_SUCCESS; /* parent admission only; final readiness below */
done:
    mHub.Status=st;return st;
}



/* Exact Open gpu_cc_hub_clk_src: clk_rcg2_ops, enable_safe_config,
 * HW_CLK_CTRL_MODE. Parent and NOM/CX ownership are already retained.
 * Never replay provider SetHz after this source handoff: its BSP clears bit20.
 */
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT32 Flags,Captured;UINT64 CmdPa,CfgPa;UINT32 Value[8][2],Vote,Bcr;
} G372_ROOT_REPORT;
#pragma pack(pop)
static G372_ROOT_REPORT mRoot;
STATIC_ASSERT(sizeof(G372_ROOT_REPORT)==148,"OGRC ABI");
static BOOLEAN RootCapture(UINTN slot)
{
 mRoot.Value[slot][0]=MmioRead32(0x03d993ec);
 mRoot.Value[slot][1]=MmioRead32(0x03d993f0);mRoot.Captured|=1u<<slot;
 return mRoot.Value[slot][0]!=MAX_UINT32&&mRoot.Value[slot][1]!=MAX_UINT32;
}
static EFI_STATUS RootPoll(UINT32 mask,UINT32 expected,UINTN slot)
{
 for(UINTN n=0;n<500;n++) {
  if(!RootCapture(slot)) return EFI_DEVICE_ERROR;
  if((mRoot.Value[slot][0]&mask)==expected) return EFI_SUCCESS;
  MicroSecondDelay(1);
 }
 return EFI_TIMEOUT;
}
static EFI_STATUS SourceRootHandoff(VOID)
{
 EFI_STATUS st=EFI_DEVICE_ERROR;UINT32 cmd,cfg;BOOLEAN own=FALSE;
 const UINT32 fields=0x0010371fu; /* HWCTL, mode, mux, HID */
 mRoot.Stage=1;
 if(!RootCapture(0)) goto done;
 MemoryFence();
 if(!RootCapture(1)) goto done;
 if(mRoot.Value[0][0]!=mRoot.Value[1][0]||mRoot.Value[0][1]!=mRoot.Value[1][1]) {st=EFI_NOT_READY;goto done;}
 cmd=mRoot.Value[1][0];cfg=mRoot.Value[1][1];
 /* Only the already demonstrated 200MHz selector/divider, no dirty/update
  * transaction or unrecognized configuration. Preserve all unrelated bits. */
 if((cmd&0xf1u)||(cfg&fields)!=0x505u) {st=EFI_UNSUPPORTED;goto done;}
 mRoot.Vote=MmioRead32(0x00152000);mRoot.Bcr=MmioRead32(0x00171000);
 if(mRoot.Vote==MAX_UINT32||mRoot.Bcr==MAX_UINT32||!(mRoot.Vote&0x8000u)||(mRoot.Bcr&1)) {st=EFI_ACCESS_DENIED;goto done;}
 mRoot.Stage=2;own=(cmd&2u)==0;
 if(own) {mRoot.Flags|=3u;MmioWrite32(0x03d993ec,cmd|2u);MemoryFence();}
 /* clk_rcg2_set_force_enable: wait ROOT_OFF clear for at most500us.
  * Unlike Linux's warn-only timeout this prototype fails closed. */
 st=RootPoll(0x80000000u,0,2);if(EFI_ERROR(st)) goto done;
 if(!(mRoot.Value[2][0]&2u)) {st=EFI_DEVICE_ERROR;goto done;}
 mRoot.Stage=3;
 if((mRoot.Value[2][1]&fields)!=0x505u||(mRoot.Value[2][0]&0xf1u)) {st=EFI_NOT_READY;goto done;}
 cfg=mRoot.Value[2][1];mRoot.Flags|=4u;
 MmioWrite32(0x03d993f0,cfg|0x00100000u);MemoryFence();
 if(!RootCapture(3)||mRoot.Value[3][1]!=(cfg|0x00100000u)) {st=EFI_DEVICE_ERROR;goto done;}
 mRoot.Stage=4;cmd=mRoot.Value[3][0];
 /* Our sole CFG write may set source-defined CFG_DIRTY bit4.
  * Its timing is not readiness. Admit only this own delta relative to the
  * captured clean forced CMD; UPDATE/M/N/D/force/unrelated changes fail. */
 if((cmd&~0x10u)!=mRoot.Value[2][0]) {st=EFI_NOT_READY;goto done;}
 mRoot.Flags|=8u;MmioWrite32(0x03d993ec,cmd|1u);MemoryFence();
 /* Exact200MHz get_update_timeout is500us; no unbounded provider retry. */
 st=RootPoll(1u,0,4);if(EFI_ERROR(st)) goto done;
 if(mRoot.Value[4][1]!=(cfg|0x00100000u)||!(mRoot.Value[4][0]&2u)) {st=EFI_DEVICE_ERROR;goto done;}
 mRoot.Stage=5;
 if(own) {
  /* Restore only our force bit, only after successful update/readback. */
  mRoot.Flags|=16u;MmioWrite32(0x03d993ec,mRoot.Value[4][0]&~2u);MemoryFence();
 }
 if(!RootCapture(5)||mRoot.Value[5][1]!=(cfg|0x00100000u)||
    ((mRoot.Value[5][0]&2u)!=((mRoot.Value[1][0])&2u))||
    (mRoot.Value[5][0]&1u)) {st=EFI_DEVICE_ERROR;goto done;}
 mRoot.Stage=6;st=EFI_SUCCESS;
done:
 /* Uncertain hardware update retains own force/parent/power votes. A blind
  * rollback could gate a root while its transaction is still pending. */
 if(EFI_ERROR(st)&&own&&!(mRoot.Flags&16u)) mRoot.Flags|=32u;
 mRoot.Status=st;return st;
}

/* G530 explicit ID-only admission, distinct from G323 enablebit policy. */
static BOOLEAN StockAhbRawReady(UINT32 raw)
{return raw!=MAX_UINT32&&((raw>>28)==0||(raw>>28)==2);}
static EFI_STATUS StockAhbQuery(UINT32 Raw)
{
 EFI_CLOCK_PROTOCOL*clock=NULL;EFI_GUID guid=EFI_CLOCK_PROTOCOL_GUID;
 EFI_STATUS st=gBS->LocateProtocol(&guid,NULL,(VOID**)&clock);mHub.RawAfter=Raw;
 if(st==EFI_SUCCESS)st=G530On(clock,Raw);
 G530_REPORT*r=G530Report();mHub.FinalQueryStatus=r->IsEnabledStatus;
 mHub.FinalEnabled=r->IsEnabled;
 if(st==EFI_SUCCESS)mHub.Stage=9; /* alternate profile, not old strict stage8 */
 mHub.Status=st;return st;
}

/* G507: one retained official domain reference, separate from external proxy
 * votes. No Disable/undo path: even a partially failed provider call is retained
 * until reset. Existing checkpoint and all report layouts stay unchanged. */
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,GetClockPowerDomainID)==80,"Clock domain GetID ABI");
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,EnableClockPowerDomain)==88,"Clock domain Enable ABI");
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT64 DomainId,LocateStatus,GetIdStatus,EnableStatus;
 UINT32 Attempted,ReturnedSuccess,RetainedAttempt,Before[2],After[2];
} G507_DOMAIN_REPORT;
#pragma pack(pop)
static G507_DOMAIN_REPORT mDomain;
static BOOLEAN mDomainAttempted;
static BOOLEAN DomainHeld(UINT32 Gds,UINT32 Hw)
{
 return Gds!=MAX_UINT32&&Hw!=MAX_UINT32&&(Gds&0x80000007u)==0x80000000u&&(Hw&0x80000000u)!=0;
}
static EFI_STATUS OfficialCxDomainLease(VOID)
{
 EFI_GUID guid=EFI_CLOCK_PROTOCOL_GUID;EFI_CLOCK_PROTOCOL *clock=NULL;
 UINTN id=MAX_UINTN;EFI_STATUS st=EFI_NOT_READY;
 if(mDomainAttempted) return EFI_ALREADY_STARTED;
 mDomainAttempted=TRUE;mDomain.Stage=1;
 mDomain.Before[0]=MmioRead32(0x03d99108);mDomain.Before[1]=MmioRead32(0x03d9953c);
 if(!DomainHeld(mDomain.Before[0],mDomain.Before[1])) goto done;
 mDomain.Stage=2;st=gBS->LocateProtocol(&guid,NULL,(VOID**)&clock);mDomain.LocateStatus=st;
 if(st!=EFI_SUCCESS) goto done;
 if(!clock||clock->Version!=0x1000a||!clock->GetClockPowerDomainID||!clock->EnableClockPowerDomain) {st=EFI_UNSUPPORTED;goto done;}
 mDomain.Stage=3;st=clock->GetClockPowerDomainID(clock,"gpu_cc_cx_gdsc",&id);
 mDomain.GetIdStatus=st;mDomain.DomainId=id;
 if(st!=EFI_SUCCESS) goto done;
 /* Exact selected BSP table24c30, node25860, stride104 -> class2/index30.
  * Sentinel/exact ID also refuses stock global-bypass success/no output. */
 if(id!=0x2001eu) {st=EFI_COMPROMISED_DATA;goto done;}
 /* Recheck immediately before the potentially synchronous provider call. */
 mDomain.Before[0]=MmioRead32(0x03d99108);mDomain.Before[1]=MmioRead32(0x03d9953c);
 if(!DomainHeld(mDomain.Before[0],mDomain.Before[1])) {st=EFI_NOT_READY;goto done;}
 mDomain.Stage=4;mDomain.Attempted=1;mDomain.RetainedAttempt=1;
 st=clock->EnableClockPowerDomain(clock,id);mDomain.EnableStatus=st;
 if(st!=EFI_SUCCESS) goto done;
 mDomain.ReturnedSuccess=1;mDomain.Stage=5;
 mDomain.After[0]=MmioRead32(0x03d99108);mDomain.After[1]=MmioRead32(0x03d9953c);
 if(!DomainHeld(mDomain.After[0],mDomain.After[1])) {st=EFI_DEVICE_ERROR;goto done;}
 mDomain.Stage=6;st=EFI_SUCCESS;
done:
 mDomain.Status=st;return st;
}

STATIC_ASSERT(sizeof(G335_CX_CONTEXT)==132,"OGCX ABI");
static CONST UINT64 mContextPa[4]={0x03d99104,0x03d993ec,0x03d993f0,0x03d9911c};
static VOID CaptureContext(UINTN Slot)
{
    BOOLEAN valid=TRUE;
    /* Called ONLY at AHB index5, after software-held CX/HW_CTRL qualified,
     * and after preceding MEMNOC/DVM admission. No new power/clock owner. */
    for(UINTN j=0;j<4;j++) {
        UINT32 v=MmioRead32((UINTN)mContextPa[j]);
        mContext.Value[Slot][j]=v;mContext.ReadMask[Slot]|=1u<<j;
        if(v==MAX_UINT32) valid=FALSE;
    }
    mContext.CapturedMask|=1u<<Slot;
    if(valid) mContext.ValidMask|=1u<<Slot;
}

static G290_POWER_REPORT mReport;static VOID *mClient[2];static BOOLEAN mAttempted;
static CONST CHAR8 *mName[2]={"/vcs/vdd_cx","/vcs/vdd_mxa"};
static CONST CHAR8 *mClientName[2]={"Open290-GPU-CX","Open290-GPU-MXA"};
/* First cfg, then CX controls, then the four exact Open SMMU clocks. */
static CONST UINT64 mPa[G290_GATES]={0x00171004,0x03d99108,0x03d9953c,
    0x00171010,0x00171018,0x03d9911c,0x03d97000};
static EFI_STATUS State(G290_NPA *N,CONST CHAR8 *Name,UINT32 *Value)
{
    G290_QUERY q;UINT32 result=MAX_UINT32;EFI_STATUS s;
    SetMem(&q,sizeof(q),0xff);s=N->Query(Name,0,&q,&result);
    if(s!=EFI_SUCCESS) return s;
    if(result||q.Type) return EFI_DEVICE_ERROR;
    *Value=q.Data.State;return EFI_SUCCESS;
}

/* Exact GPUCC provider registration proxy contract: all three classes are
 * VDD_HIGH+1, so num_levels-1 is VDD_HIGH -> RPMH TURBO384 VLVL.
 * Runtime NOM256 requests above remain independent; no enum index/uV/ARC use.
 */
#define G416_PROXY_VLVL 384u
#define G416_PROXY_MAX_VLVL 480u
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT32 Requested,ClientType,CreatedMask,IssuedMask,ReturnedMask,ObservedMask,RetainedMask;
 UINT32 Before[3],After[3],Final[3],AvailableResult[3];
 UINT64 AvailableStatus[3],CreateStatus[3],RequestStatus[3];
 UINT64 BeforeQueryStatus[3],AfterQueryStatus[3],FinalQueryStatus[3];
} G416_PROXY_REPORT;
#pragma pack(pop)
static G416_PROXY_REPORT mProxy;
STATIC_ASSERT(sizeof(G416_PROXY_REPORT)==272,"OGPV ABI");
static VOID*mProxyClient[3];
static CONST CHAR8*mProxyName[3]={"/vcs/vdd_cx","/vcs/vdd_mxa","/vcs/vdd_mxc"};
static CONST CHAR8*mProxyClientName[3]={"Open416-GPUCC-Proxy-CX","Open416-GPUCC-Proxy-MXA","Open416-GPUCC-Proxy-MXC"};
#define G726_GX_DECOLLAPSE() do{UINT32 hw=MmioRead32(0x03d9953c);\
   if(hw!=MAX_UINT32&&(hw&(1u<<31))){MmioWrite32(0x03d9953c,hw&~(1u<<31));MemoryFence();gBS->Stall(3);}\
   {UINT32 gx_=MmioRead32(0x03d9905c);\
    if(gx_!=MAX_UINT32){\
     if(gx_&1u){MmioWrite32(0x03d9905c,gx_&~1u);MemoryFence();gBS->Stall(2);}\
     for(UINTN i_=0;i_<300;i_++){gx_=MmioRead32(0x03d9905c);\
      if(gx_!=MAX_UINT32&&(gx_&(1u<<31)))break;gBS->Stall(10);}}}}while(0)
static UINT32 mG727Trail[13]; /* GX rail probe trail: [0]dscr-entry [1]hwctl0 [2]hwctl1 [3..10]per-candidate [11]final [12]flags */
static VOID G721DirectRootSequence(VOID); /* G721: defined below ProviderProxy */
static BOOLEAN G722Pll1Ready(VOID);static EFI_STATUS G722Pll1Program(VOID);
static EFI_STATUS ProviderProxy(G290_NPA*n)
{
 EFI_STATUS st;UINT32 state;
 mProxy.Stage=1;
 /* Resolve/query every exact provider class before acquiring anything new. */
 for(UINTN i=0;i<3;i++) {
  st=n->Available(mProxyName[i],&mProxy.AvailableResult[i]);mProxy.AvailableStatus[i]=st;
  if(st!=EFI_SUCCESS)goto done;
  if(mProxy.AvailableResult[i]){st=EFI_NOT_READY;goto done;}
  st=State(n,mProxyName[i],&state);mProxy.BeforeQueryStatus[i]=st;
  if(st!=EFI_SUCCESS)goto done;mProxy.Before[i]=state;
  if(state>G416_PROXY_MAX_VLVL){st=EFI_DEVICE_ERROR;goto done;}
 }
 mProxy.Stage=2;
 for(UINTN i=0;i<3;i++) {
  st=n->Create(mProxyName[i],mProxyClientName[i],0x40,0,NULL,&mProxyClient[i]);
  mProxy.CreateStatus[i]=st;
  /* RetainedMask records a returned nonnull pointer kept privately, even
   * if rejected below; it does not certify accepted independent ownership. */
  if(mProxyClient[i])mProxy.RetainedMask|=1u<<i;
  if(st!=EFI_SUCCESS)goto done;
  if(!mProxyClient[i]){st=EFI_DEVICE_ERROR;goto done;}
  for(UINTN j=0;j<2;j++)if(mProxyClient[i]==mClient[j]){st=EFI_DEVICE_ERROR;goto done;}
  for(UINTN j=0;j<i;j++)if(mProxyClient[i]==mProxyClient[j]){st=EFI_DEVICE_ERROR;goto done;}
  mProxy.CreatedMask|=1u<<i; /* only status0 + nonnull + distinct */
 }
 /* Source clk_vdd_proxy_vote visits CX,MXA,MXC in provider-array order.
  * Supported synchronous Request retains the existing internal liveness
  * limitation; no false timeout, raw rail access or automatic unwind. */
 for(UINTN i=0;i<3;i++) {
  mProxy.Stage=3+(UINT32)i;mProxy.IssuedMask|=1u<<i;
  st=n->Request(mProxyClient[i],G416_PROXY_VLVL);mProxy.RequestStatus[i]=st;
  if(st!=EFI_SUCCESS)goto done;mProxy.ReturnedMask|=1u<<i;
  st=State(n,mProxyName[i],&state);mProxy.AfterQueryStatus[i]=st;
  if(st!=EFI_SUCCESS)goto done;mProxy.After[i]=state;
  if(state>G416_PROXY_MAX_VLVL||state<G416_PROXY_VLVL){st=EFI_DEVICE_ERROR;goto done;}
  mProxy.ObservedMask|=1u<<i;
 }
 mProxy.Stage=6;
 /* G727: GFX rail diagnosing probe. For EACH candidate NPA name that
  * resolves: vote 384, wait 100ms rail ramp, clear HW_CTRL + de-collapse,
  * read GDSCR immediately. Trail recorded in OGR7.GxDscr[1..8]. Any name
  * whose GDSCR bit31 sets wins (repeat vote at end to hold it). */
 {static CONST CHAR8*gfxNames[]={"/vcs/vdd_gx","/vdd/gfx","/gpu/gfx","/vcs/vdd_gfx","/vdd/gx","/gfx/lvl","/vcs/gfx"};
  VOID*clients[8]={0};UINTN winner=0;
  mG727Trail[0]=MmioRead32(0x03d9905c);
  mG727Trail[1]=MmioRead32(0x03d9953c);
  if(mG727Trail[1]!=MAX_UINT32&&(mG727Trail[1]&(1u<<31)))
   {MmioWrite32(0x03d9953c,mG727Trail[1]&~(1u<<31));MemoryFence();gBS->Stall(3);}
  mG727Trail[2]=MmioRead32(0x03d9953c);
  UINTN resolved=0;
  for(UINTN i=0;i<7;i++){
   UINT32 st2=0;
   EFI_STATUS a=n->Available(gfxNames[i],&st2);
   if(a!=EFI_SUCCESS||st2){mG727Trail[3+i]=MAX_UINT32;continue;}
   resolved++;
   EFI_STATUS c=n->Create(gfxNames[i],"Open727-GFX-Probe",0x40,0,NULL,&clients[i]);
   if(c!=EFI_SUCCESS||!clients[i]){mG727Trail[3+i]=0xDEAD0000u+(UINT32)i;continue;}
   (VOID)n->Request(clients[i],G416_PROXY_VLVL);
   gBS->Stall(100000); /* 100ms rail ramp */
   G726_GX_DECOLLAPSE();
   mG727Trail[3+i]=MmioRead32(0x03d9905c);
   if(mG727Trail[3+i]!=MAX_UINT32&&(mG727Trail[3+i]&(1u<<31))){winner=1+i;mG727Trail[12]|=2u;break;}
  }
  if(resolved>1)mG727Trail[12]|=1u;
  if(!winner){ /* second pass: raise corner to 448 on every resolved client */
   for(UINTN i=0;i<7;i++){
    if(!clients[i])continue;
    (VOID)n->Request(clients[i],448u);
    gBS->Stall(100000);
    G726_GX_DECOLLAPSE();
    UINT32 v=MmioRead32(0x03d9905c);
    if(v!=MAX_UINT32&&(v&(1u<<31))){winner=1+i;mG727Trail[12]|=2u;mG727Trail[3+i]=v;break;}
   }}
  mG727Trail[11]=MmioRead32(0x03d9905c);
  mProxy.RetainedMask|=(winner?(8u):(0u));
  mProxy.ClientType|=winner?(winner<<8):(0u);
 }
 mProxy.Stage=6;
 for(UINTN i=0;i<3;i++) {
  st=State(n,mProxyName[i],&state);mProxy.FinalQueryStatus[i]=st;
  if(st!=EFI_SUCCESS)goto done;mProxy.Final[i]=state;
  if(state>G416_PROXY_MAX_VLVL||state<G416_PROXY_VLVL){st=EFI_DEVICE_ERROR;goto done;}
 }
 /* OGPR's two legacy aggregate fields now show the final pre-MMIO levels,
  * not the earlier NOM-only intermediate values. Its old masks stay2bits. */
 mReport.CornerAfter[0]=mProxy.Final[0];mReport.CornerAfter[1]=mProxy.Final[1];
 mProxy.Stage=7;
 /* G719: GX domain enable attempt. /vcs NPA has no gx rail (supply is the
  * gfx.lvl ARC), so try the direct GDSC order with the voted parents HIGH:
  * clear SW_COLLAPSE bit0, barrier, poll ON bit31 (1500us). Non-fatal. */
 if(st==EFI_SUCCESS){
  #define GX_GDSCR 0x03d9905cu
  static UINT32 sGxScr=0;UINT32 gx=MmioRead32(GX_GDSCR);sGxScr=gx;
  if(gx!=MAX_UINT32){
   if(gx&1u){
    MmioWrite32(GX_GDSCR,gx&~1u);MemoryFence();
    gBS->Stall(2);
    for(UINTN i=0;i<150;i++){
     gx=MmioRead32(GX_GDSCR);
     if(gx!=MAX_UINT32&&(gx&(1u<<31)))break;
     gBS->Stall(10);
    }
    sGxScr=gx;MemoryFence();
   } else if(gx&(1u<<31)){sGxScr=gx;}
  }
 }
 /* G721: DIRECT root-first clock sequence, no provider dependency.
  * Order per open-gpucc-kalama.c topology: GPLL0 vote -> hub RCG
  * (200MHz=GPLL0/3: src5 hid5 HW_CLK_CTRL bit20) -> hub_cx_int branch ->
  * AHB branch (HALT_DELAY semantics) -> gmu RCG (19.2MHz BI_TCXO: src0 hid1)
  * -> cx_gmu/cxo branches. Runs BEFORE the G720 leaves so leaves get live
  * roots. Non-fatal; every value recorded in the OGR7 table. */
 G721DirectRootSequence();
 /* G722-r: GMU-specific leaves (cx_gmu 0x3d9913c / cxo 0x3d99144) REMOVED:
  * the broker FSM must find them off (rerate FOREIGN precondition). GCC
  * memnoc/dvm branches + hub_cx_int + AHB-observe remain. Non-fatal. */
 {
  static CONST UINT64 mLeaf[4]={0x00171000+0x154,0x00171010,0x03d9911c,0x03d99148};
  for(UINTN i=0;i<4;i++){
   UINT32 v=MmioRead32(mLeaf[i]);MemoryFence();
   if(v==MAX_UINT32)continue;
   if(!(v&1u)&&i!=2){MmioWrite32(mLeaf[i],v|1u);MemoryFence();gBS->Stall(2);}
   for(UINTN n=0;n<200;n++){
    v=MmioRead32(mLeaf[i]);MemoryFence();
    if(v==MAX_UINT32)break;
    if(i==2)break; /* AHB: aggregate owner semantics; just observe */
    if((v&1u)&&!(v&0x80000000u))break;
    gBS->Stall(1);
   }
  }
 }
done:mProxy.Status=st;return st;
}

/* ---- G721: direct root-first GPU clock sequence (no clock-protocol calls) ---- */
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT32 Flags,CxScr;
 UINT32 GpllMode,GpllLock,VoteReg;
 UINT32 HubCmd[2],HubCfg[2],HubCxInt[2],Ahb[2];
 UINT32 GmuCmd[2],GmuCfg[2],CxGmu[2],Cxo[2];
 /* G727 GX rail trail: GxHwCtl[2]=0x3d9953c before/after, GxDscr[0]=entry,
  * [1..8]=GDSCR after each candidate vote+ramp, GxDscrFinal=last, GxFlags
  * bits: 1=multiple-names-resolved 2=any-rail-lift */
 UINT32 GxHwCtl[2],GxDscr[9],GxDscrFinal,GxFlags;
}G721_ROOT_REPORT;
#pragma pack(pop)
static G721_ROOT_REPORT mR721;
/* Flags: 1=gpll-inactive-at-entry 2=gpll-direct-vote-failed 4=gpll-voted-direct
 * 8=gpll-already-active 16=hub-rcg-failed 32=hub_cx_int-failed 64=ahb-not-sticky
 * (128/256/512 retired in G722: gmu rcg+leaves are broker-owned, observe-only)
 * 1024=pll1-inactive-at-entry 2048=pll1-program-FAILED 4096=pll1-programmed
 * 8192=pll1-already-active */
static UINT32 R721Read(UINT64 pa){MemoryFence();UINT32 v=MmioRead32((UINTN)pa);MemoryFence();return v;}
static EFI_STATUS R721Poll(UINT64 pa,UINT32 mask,UINT32 expected,UINTN budgetUs){
 for(UINTN t=0;t<=budgetUs;t+=5){
  UINT32 v=R721Read(pa);
  if(v==MAX_UINT32)return EFI_DEVICE_ERROR;
  if((v&mask)==expected)return EFI_SUCCESS;
  gBS->Stall(5);
 }
 return EFI_TIMEOUT;
}
static BOOLEAN G721GpllActive(VOID){
 UINT32 a=R721Read(0x00152000),b=R721Read(0x00100000);
 mR721.GpllMode=a;mR721.GpllLock=b;
 if(a==MAX_UINT32||b==MAX_UINT32)return FALSE;
 if(!(a&0x8000u)||!(b&0x80000000u))return FALSE;
 UINT32 s[2][6];PllSnapshot(s);
 if(!G400PllStable600((CONST uint32_t(*)[6])s))return FALSE;
 gBS->Stall(20);PllSnapshot(s);
 return G400PllStable600((CONST uint32_t(*)[6])s);
}
static EFI_STATUS G721GpllVoteDirect(VOID){
 UINT32 v=R721Read(0x00152018);
 if(v==MAX_UINT32)return EFI_DEVICE_ERROR;
 if(v&1u){mR721.VoteReg=v;return R721Poll(0x00100000,0x80000000u,0x80000000u,500);}
 EFI_TPL tpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 UINT32 w=R721Read(0x00152018);
 if(w!=v||w==MAX_UINT32){gBS->RestoreTPL(tpl);return EFI_NOT_READY;}
 MmioWrite32(0x00152018,w|1u);MemoryFence();
 gBS->RestoreTPL(tpl);
 mR721.VoteReg=R721Read(0x00152018);
 return R721Poll(0x00100000,0x80000000u,0x80000000u,500);
}
/* Mirrors the proven SourceRootHandoff write pattern (ROOT_EN -> poll
 * ROOT_OFF clear -> CFG -> UPDATE -> poll UPDATE clear) without its
 * requires-CFG-already-0x505 precondition. fields mask 0x0010371f. */
static EFI_STATUS G721RcgProgram(UINT64 cmdPa,UINT32 cfgValue){
 UINT32 cmd=R721Read(cmdPa);
 if(cmd==MAX_UINT32)return EFI_DEVICE_ERROR;
 if(!(cmd&2u)){MmioWrite32((UINTN)cmdPa,cmd|2u);MemoryFence();}
 EFI_STATUS st=R721Poll(cmdPa,0x80000000u,0,500);
 if(EFI_ERROR(st))return st;
 UINT32 cfg=R721Read(cmdPa+4);
 if(cfg==MAX_UINT32)return EFI_DEVICE_ERROR;
 UINT32 nc=(cfg&~0x0010371fu)|cfgValue;
 if(nc!=cfg){MmioWrite32((UINTN)(cmdPa+4),nc);MemoryFence();}
 cmd=R721Read(cmdPa);
 if(cmd==MAX_UINT32)return EFI_DEVICE_ERROR;
 MmioWrite32((UINTN)cmdPa,cmd|1u);MemoryFence();
 st=R721Poll(cmdPa,1u,0,500);
 if(EFI_ERROR(st))return st;
 UINT32 chk=R721Read(cmdPa+4);
 if(chk==MAX_UINT32||chk!=nc)return EFI_DEVICE_ERROR;
 if(!(R721Read(cmdPa)&2u))return EFI_DEVICE_ERROR;
 return EFI_SUCCESS;
}
/* Enabling HALT/HALT_VOTED branch: bit0 set, OFF bit31 clear. */
static EFI_STATUS G721BranchOn(UINT64 pa){
 UINT32 v=R721Read(pa);
 if(v==MAX_UINT32)return EFI_DEVICE_ERROR;
 if(!(v&1u)){MmioWrite32((UINTN)pa,v|1u);MemoryFence();}
 return R721Poll(pa,0x80000001u,0x00000001u,500);
}
static VOID G721DirectRootSequence(VOID){
 mR721.Stage=1;mR721.CxScr=R721Read(0x03d99104); /* observed, never written */
 if(!G721GpllActive()){
  mR721.Flags|=1u;
  if(EFI_ERROR(G721GpllVoteDirect())){mR721.Flags|=2u;goto done;}
  mR721.Flags|=4u;
 } else mR721.Flags|=8u;
 mR721.Stage=2;
 mR721.HubCmd[0]=R721Read(0x03d993ec);mR721.HubCfg[0]=R721Read(0x03d993f0);
 if(EFI_ERROR(G721RcgProgram(0x03d993ec,(5u<<8)|5u|0x00100000u))){mR721.Flags|=16u;goto gmu;}
 mR721.HubCmd[1]=R721Read(0x03d993ec);mR721.HubCfg[1]=R721Read(0x03d993f0);
 mR721.Stage=3;
 mR721.HubCxInt[0]=R721Read(0x03d99148);
 if(EFI_ERROR(G721BranchOn(0x03d99148))){mR721.Flags|=32u;goto gmu;}
 mR721.HubCxInt[1]=R721Read(0x03d99148);
 mR721.Stage=4;
 /* AHB is BRANCH_HALT_DELAY: write bit0, fixed 10us, observe. */
 mR721.Ahb[0]=R721Read(0x03d9911c);
 {UINT32 v=mR721.Ahb[0];
  if(v!=MAX_UINT32&&!(v&1u)){MmioWrite32(0x03d9911c,v|1u);MemoryFence();}
  gBS->Stall(10);}
 mR721.Ahb[1]=R721Read(0x03d9911c);
 if(mR721.Ahb[1]!=MAX_UINT32&&!(mR721.Ahb[1]&1u))mR721.Flags|=64u;
gmu:
 /* G723: GPU-core-block reachability clocks (the phase-8 0x483 blocker:
  * CghCheck reads GBIF CX halt regs at GPU+0xf114/f118 -> physical read
  * fails with only hub/cx_gmu on). Add per open-gpucc-kalama:
  *   hub_aon 0x3d993e8 (BRANCH_HALT, parent hub src)
  *   crc_ahb 0x3d99120 (BRANCH_HALT_VOTED, parent hub src)
  *   AHB retry 0x3d9911c with longer settle
  *   ff RCG 0x3d99474 (200MHz GPLL0/3 = same CFG as hub; parent_map_0 GPLL0=5)
  *   cx_ff 0x3d9914c (BRANCH_HALT, parent ff src)
  * All outside the broker FSM's owned set; non-fatal, readbacks recorded. */
 {UINT32 v=R721Read(0x03d993e8);
  if(v!=MAX_UINT32&&!(v&1u)){MmioWrite32(0x03d993e8,v|1u);MemoryFence();gBS->Stall(2);}
  if(EFI_ERROR(R721Poll(0x03d993e8,0x80000001u,0x00000001u,500)))mR721.Flags|=32768u;}
 {UINT32 v=R721Read(0x03d99120);
  if(v!=MAX_UINT32&&!(v&1u)){MmioWrite32(0x03d99120,v|1u);MemoryFence();gBS->Stall(2);}
  if(EFI_ERROR(R721Poll(0x03d99120,0x80000001u,0x00000001u,500)))mR721.Flags|=65536u;}
 {UINT32 v=R721Read(0x03d9911c);
  if(v!=MAX_UINT32&&!(v&1u)){MmioWrite32(0x03d9911c,v|1u);MemoryFence();gBS->Stall(100);}
  if(R721Read(0x03d9911c)==MAX_UINT32||!(R721Read(0x03d9911c)&1u))mR721.Flags|=131072u;}
 if(EFI_ERROR(G721RcgProgram(0x03d99474,(5u<<8)|5u|0x00100000u)))mR721.Flags|=262144u;
 {UINT32 v=R721Read(0x03d9914c);
  if(v!=MAX_UINT32&&!(v&1u)){MmioWrite32(0x03d9914c,v|1u);MemoryFence();gBS->Stall(2);}
  if(EFI_ERROR(R721Poll(0x03d9914c,0x80000001u,0x00000001u,500)))mR721.Flags|=524288u;}
 /* G722: the GMU RCG (0x3d99318/0x3d9931c) and the cx_gmu/cxo leaves are
  * OWNED by the broker KMD clock FSM (gmu_clock.c GmcAcquire): it refuses
  * with GMC_FOREIGN if the GMU RCG CMD has bits 0xf3 set (ROOT_EN!) or if
  * cx_gmu bit0 is already on at its 220MHz rerate. Firmware leaves them
  * untouched; observe only for the evidence table. */
 mR721.Stage=5;
 mR721.GmuCmd[0]=R721Read(0x03d99318);mR721.GmuCfg[0]=R721Read(0x03d9931c);
 mR721.CxGmu[0]=R721Read(0x03d9913c);mR721.Cxo[0]=R721Read(0x03d99144);
 /* G722: GPU_CC PLL1 @0x3d91000 (LUCID_OLE) to 440MHz per the vendor
  * gpu_cc_pll1_config. The broker's pll() preconditions: MODE LOCK|RESET_N|
  * OUTCTRL (0x80000005), OPMODE==RUN(1), USER_CTL bit0, and rate in
  * 439999000..440001000 kHz window (l=0x16 alpha=0xEAAA -> 439.9995MHz).
  * Sequence = clk_lucid_evo_pll_configure + alpha_pll_lucid_evo_enable. */
 if(!G722Pll1Ready()){
  mR721.Flags|=1024u;
  if(EFI_ERROR(G722Pll1Program())){mR721.Flags|=2048u;goto done;}
  mR721.Flags|=4096u;
 } else mR721.Flags|=8192u;
 /* G722-r2: cx_gmu(0x3d9913c)/cxo(0x3d99144) are AON branches that POWER UP
  * ENABLED (observed 0x2001/0x1 on a clean boot). The broker's GmcAcquire
  * rerate precondition requires before[0] (cx_gmu) bit0==0 and gxleaf
  * (0x3d990bc) bit0==0 -> clear them so the FSM can own and enable them. */
 {static CONST UINT64 off[3]={0x03d9913c,0x03d99144,0x03d990bc};
  for(UINTN i=0;i<3;i++){
   UINT32 v=R721Read(off[i]);
   if(v==MAX_UINT32)continue;
   if(v&1u){MmioWrite32((UINTN)off[i],v&~1u);MemoryFence();gBS->Stall(5);}
   v=R721Read(off[i]);
   if(v!=MAX_UINT32&&(v&1u))mR721.Flags|=16384u; /* clear-failed, recorded */
  }}
 mR721.GmuCmd[1]=R721Read(0x03d99318);mR721.GmuCfg[1]=R721Read(0x03d9931c);
 mR721.CxGmu[1]=R721Read(0x03d9913c);mR721.Cxo[1]=R721Read(0x03d99144);
 mR721.Stage=7;
done:
 if(mR721.Stage>=7&&!(mR721.Flags&(16u|32u|2048u)))mR721.Status=EFI_SUCCESS;
 else if(mR721.Stage>=2)mR721.Status=EFI_NOT_READY;
 else mR721.Status=EFI_DEVICE_ERROR;
}
/* ---- G722: GPU_CC PLL1 (LUCID_OLE, base 0x3d91000) 440MHz owner ---- */
static BOOLEAN G722Pll1Ready(VOID){
 UINT32 mode=R721Read(0x03d91000),op=R721Read(0x03d91004);
 UINT32 l=R721Read(0x03d91010),alpha=R721Read(0x03d91014),user=R721Read(0x03d91018);
 if(mode==MAX_UINT32||op==MAX_UINT32||l==MAX_UINT32||alpha==MAX_UINT32||user==MAX_UINT32)return FALSE;
 return (mode&0x80000005u)==0x80000005u&&op==1u&&(user&1u)&&
        (l&0xffffu)==0x16u&&(alpha&0xffffu)==0xEAAAu;
}
static EFI_STATUS G722Pll1Program(VOID){
 UINT32 v;
 /* configure: L(L=0x16 | process_cal_l=0x44<<16 | ringosc=0x44<<24), ALPHA,
  * CONFIG_CTL 0x20485699 / U 0x00182261 / U1 0x82AA299C, USER_CTL_U 0x5,
  * TEST_CTL_U 0x3 / U1 0x9000 / U2 0x34 (test_ctl_val=0 -> skipped),
  * clear MODE OUTCTRL, OPMODE=STANDBY(0), MODE|=RESET_N(bit2). */
 MmioWrite32(0x03d91010,0x44440016u);MemoryFence();
 MmioWrite32(0x03d91014,0x0000EAAAu);MemoryFence();
 MmioWrite32(0x03d91020,0x20485699u);MemoryFence();
 MmioWrite32(0x03d91024,0x00182261u);MemoryFence();
 MmioWrite32(0x03d91028,0x82AA299Cu);MemoryFence();
 MmioWrite32(0x03d9101c,0x00000005u);MemoryFence();
 MmioWrite32(0x03d91030,0x00000003u);MemoryFence();
 MmioWrite32(0x03d91034,0x00009000u);MemoryFence();
 MmioWrite32(0x03d91038,0x00000034u);MemoryFence();
 v=R721Read(0x03d91000);
 if(v==MAX_UINT32)return EFI_DEVICE_ERROR;
 MmioWrite32(0x03d91000,v&~1u);MemoryFence(); /* OUTCTRL off */
 MmioWrite32(0x03d91004,0u);MemoryFence();    /* OPMODE STANDBY */
 v=R721Read(0x03d91000);
 MmioWrite32(0x03d91000,v|4u);MemoryFence();  /* RESET_N de-asserted */
 /* enable: OPMODE=RUN, poll MODE LOCK bit31, USER_CTL|=OUT(bit0), MODE|=OUTCTRL */
 MmioWrite32(0x03d91004,1u);MemoryFence();
 EFI_STATUS st=R721Poll(0x03d91000,0x80000000u,0x80000000u,1000);
 if(EFI_ERROR(st))return st;
 UINT32 user=R721Read(0x03d91018);
 if(user==MAX_UINT32)return EFI_DEVICE_ERROR;
 MmioWrite32(0x03d91018,user|1u);MemoryFence();
 v=R721Read(0x03d91000);
 if(v==MAX_UINT32)return EFI_DEVICE_ERROR;
 MmioWrite32(0x03d91000,v|1u);MemoryFence();  /* OUTCTRL */
 /* final readback = the broker's pll() preconditions exactly */
 v=R721Read(0x03d91000);
 if(v==MAX_UINT32||(v&0x80000005u)!=0x80000005u)return EFI_DEVICE_ERROR;
 if(R721Read(0x03d91004)!=1u)return EFI_DEVICE_ERROR;
 if(!(R721Read(0x03d91018)&1u))return EFI_DEVICE_ERROR;
 return EFI_SUCCESS;
}

static UINT32 Read(UINTN Index)
{return MmioRead32((UINTN)mPa[Index]);}
static EFI_STATUS Poll(UINTN Index,UINT32 Mask,UINT32 Expected,UINTN BudgetUs)
{
    for(UINTN elapsed=0;;elapsed+=10) {
        UINT32 v=Read(Index);mReport.Gate[Index].After=v;
        if(v==MAX_UINT32) return EFI_DEVICE_ERROR;
        if((v&Mask)==Expected) return EFI_SUCCESS;
        if(elapsed>=BudgetUs) return EFI_TIMEOUT;
        MicroSecondDelay(10);
    }
}
/* G314-r2 standard GCD/CpuArch admission; adapted from reviewed G310-r2. */
static EFI_STATUS PrepareMappings(void){
 /* Source-declared provider controller apertures only. Translation is not
  * power qualification and performs no target MMIO access. Partial mappings
  * remain until full reset on failure; no unwind or automatic retry. */
 static const struct{UINT64 Base,Length;} R[]={
  /* Exact declared controller apertures for stock ClockDxe internals. Mapping
   * precedes provider calls; it is not permission for arbitrary MMIO access.
   * GCC matches the already reviewed WiFi provider binding; GPUCC covers its
   * Open register max0x9988. Do not rely on later WiFi ReadyToBoot mapping. */
  {0x00100000,0x1f5000}, {0x03d90000,0xa000}, {0x03da0000,0x1000}
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
static EFI_STATUS MappingPreflight(VOID)
{
    EFI_STATUS admission=PrepareMappings();
    if(EFI_ERROR(admission)) return admission;
    static CONST EFI_PHYSICAL_ADDRESS pages[4]={0x00171000,0x03d97000,0x03d99000,0x03da0000};
    for(UINTN i=0;i<4;i++) {
        EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;EFI_STATUS s=gDS->GetMemorySpaceDescriptor(pages[i],&d);
        if(EFI_ERROR(s)) return s;
        if(d.GcdMemoryType!=EfiGcdMemoryTypeMemoryMappedIo||!(d.Attributes&EFI_MEMORY_UC)||
           d.BaseAddress>pages[i]||d.Length<0x1000||pages[i]-d.BaseAddress>d.Length-0x1000)
            return EFI_NOT_READY;
    }
    return EFI_SUCCESS;
}
#pragma pack(push,1)
typedef struct {G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;UINT32 Gdscr[2],Cfg[2],CapturedMask,ColdGxOff;UINT32 Ready,WindowsRailLease;}CXB_GX_REPORT;
#pragma pack(pop)
static CXB_GX_REPORT mGx;
static EFI_STATUS RequireGxOff(UINTN index){
 UINT32 a=MmioRead32(0x03d9905c),b=MmioRead32(0x03d99060);MemoryFence();
 UINT32 c=MmioRead32(0x03d9905c),d=MmioRead32(0x03d99060);
 mGx.Gdscr[index]=c;mGx.Cfg[index]=d;mGx.CapturedMask|=1u<<index;
 if(a==MAX_UINT32||b==MAX_UINT32||a!=c||b!=d)return EFI_DEVICE_ERROR;
 /* Exact GX DT support-cfg-gdscr: gdsc poll DISABLED is CFGbit15.
  * Require current SW_COLLAPSE request too. Never infer from GDSCR31.
  * This qualifies GXoff only; it does not claim CM3/HFI/GBIF stop. */
 if(!(c&1u)||!(d&(1u<<15)))return EFI_NOT_READY;
 return EFI_SUCCESS;
}
static EFI_STATUS Prepare(VOID)
{
    G290_NPA *n=NULL;EFI_STATUS s;UINT32 value;
    s=MappingPreflight();if(s!=EFI_SUCCESS) return s;
    s=RequireGxOff(0);if(s!=EFI_SUCCESS)return s;
    s=gBS->LocateProtocol(&mNpaGuid,NULL,(VOID**)&n);
    if(s!=EFI_SUCCESS) return s;
    if(!n||n->Version!=0x10003||!n->Create||!n->Request||!n->Available||!n->Query)
        return EFI_UNSUPPORTED;
    mReport.Stage=1;
    for(UINTN i=0;i<2;i++) {
        UINT32 result=MAX_UINT32;s=n->Available(mName[i],&result);
        if(s!=EFI_SUCCESS) return s;if(result) return EFI_NOT_READY;
        UINT32 state;s=State(n,mName[i],&state);if(s!=EFI_SUCCESS) return s;
        mReport.CornerBefore[i]=state;
    }
    mReport.Stage=2;
    for(UINTN i=0;i<2;i++) {
        s=n->Create(mName[i],mClientName[i],0x40,0,NULL,&mClient[i]);
        if(mClient[i]) mReport.CreatedMask|=1u<<i;
        if(s!=EFI_SUCCESS) return s;if(!mClient[i]) return EFI_DEVICE_ERROR;
        if(i&&mClient[0]==mClient[1]) return EFI_DEVICE_ERROR;
    }
    mReport.Stage=3;
    for(UINTN i=0;i<2;i++) {
        /* Corrected r1: exact Open NOM256 covers declared hub/AHB rates
         * through400MHz. No GPU render clock/rate is changed; units are VLVL
         * corners, not uV or ARC indices.
         * This stock synchronous Request can internally wait without bound. */
        mReport.IssuedMask|=1u<<i;s=n->Request(mClient[i],G290_GPU_CORNER);
        if(s!=EFI_SUCCESS) return s;mReport.ReturnedMask|=1u<<i;
        UINT32 state;s=State(n,mName[i],&state);if(s!=EFI_SUCCESS) return s;
        mReport.CornerAfter[i]=state;
        if(mReport.CornerAfter[i]<G290_GPU_CORNER) return EFI_DEVICE_ERROR;
        mReport.ObservedMask|=1u<<i;
    }
    s=ProviderProxy(n);if(s!=EFI_SUCCESS)return s;
    /* Actual MMIO begins only after both runtime NOM requests and allthree
     * provider HIGH384 proxy requests returned/observed; votes stayowned. */
    mReport.Stage=4;
    value=Read(0);mReport.Gate[0].Before=value;
    if(value==MAX_UINT32) return EFI_DEVICE_ERROR;
    if(!(value&1)) {MmioWrite32((UINTN)mPa[0],value|1);MemoryFence();}
    mReport.Gate[0].After=Read(0);
    if(!(mReport.Gate[0].After&1)||mReport.Gate[0].After==MAX_UINT32) return EFI_NOT_READY;
    mReport.Stage=5;
    value=Read(1);mReport.Gate[1].Before=value;mReport.Gate[1].After=value;
    mReport.Gate[2].Before=Read(2);mReport.Gate[2].After=mReport.Gate[2].Before;
    if(value==MAX_UINT32||mReport.Gate[2].Before==MAX_UINT32) return EFI_DEVICE_ERROR;
    /* Establish a software-held domain vote even if another boot consumer
     * currently keeps HW_CTRL on. Do not borrow an HW-controlled domain. */
    if(value&2) return EFI_ACCESS_DENIED;
    if(value&1) {MmioWrite32((UINTN)mPa[1],value&~1u);MemoryFence();MicroSecondDelay(1);}
    s=Poll(2,0x80000000u,0x80000000u,1500);if(s!=EFI_SUCCESS) return s;
    MicroSecondDelay(2);mReport.Gate[1].After=Read(1);
    if(mReport.Gate[1].After&3) return EFI_DEVICE_ERROR;
    mReport.Stage=6;
    /* Exact selected DT clock-names order; report gate indexes stay stable.
     * SMMUvote -> MEMNOC -> DVM -> AHB. Parent/root setup is part of AHB.
     * Never infer safety of a different sequence from final after-values. */
    static CONST UINTN ClockOrder[4]={6,3,4,5};
    for(UINTN step=0;step<4;step++) {
        UINTN i=ClockOrder[step];
        if(i==5) {
            CaptureContext(0);
            /* G721: if the direct root sequence already brought hub root+AHB
             * up, the provider-dependent handoff chain is skipped entirely:
             * SourceRootHandoff's precondition (CFG bit20 clear) no longer
             * holds after a successful direct program, by design. */
            if(mR721.Status==EFI_SUCCESS) {CaptureContext(1);mHub.Status=EFI_SUCCESS;mHub.Stage=6;}
            else {
            s=OfficialCxDomainLease();
            if(s!=EFI_SUCCESS) {CaptureContext(1);return s;}
            s=GpllPreflight();
            if(s!=EFI_SUCCESS) {CaptureContext(1);return s;}
            s=ExternalParentLease();
            if(s!=EFI_SUCCESS) {CaptureContext(1);return s;}
            s=GpllVote();
            if(s!=EFI_SUCCESS) {CaptureContext(1);return s;}
            s=HubThroughProvider();
            if(s!=EFI_SUCCESS) {CaptureContext(1);return s;}
            s=SourceRootHandoff();
            if(s!=EFI_SUCCESS) {CaptureContext(1);return s;}
            }
        }
        if(i==5) mHub.Stage=6;
        value=Read(i);mReport.Gate[i].Before=value;
        if(i==5) mHub.RawBefore=value;
        if(value==MAX_UINT32) {
            if(i==5) {mHub.Status=EFI_DEVICE_ERROR;CaptureContext(1);}
            return EFI_DEVICE_ERROR;
        }
        if(!(value&1)) {
            if(i==5) mHub.DirectAttempted=1;
            MmioWrite32((UINTN)mPa[i],value|1);MemoryFence();
        }
        /* Exact source policy: MEMNOC skips halt while HWCGbit1 is set;
         * DVM and GPU-AHB use10us delay; SMMU vote retains halt polling. */
        if(i==4||i==5) MicroSecondDelay(10);
        s=EFI_SUCCESS;
        for(UINTN elapsed=0;;elapsed+=10) {
            value=Read(i);mReport.Gate[i].After=value;
            if(i==5?StockAhbRawReady(value):G323BranchReady((unsigned)i,value)) break;
            if(value==MAX_UINT32) {s=EFI_DEVICE_ERROR;break;}
            if(elapsed>=500) {s=EFI_TIMEOUT;break;}
            MicroSecondDelay(10);
        }
        if(i==5) {
            mHub.RawAfter=mReport.Gate[i].After;
            if(s==EFI_SUCCESS) s=StockAhbQuery(mReport.Gate[i].After);
            else mHub.Status=s;
            CaptureContext(1);
        }
        if(s!=EFI_SUCCESS) return s;
    }
    /* Real power/clock requests have completed. Stop BEFORE GR0/CB/GMU.
     * Actual Windows D0 and cold producer must independently requalify. */
    /* G726: HW_CTRL clear + final de-collapse; leave GX powered across EBS */
    G726_GX_DECOLLAPSE();
    mGx.ColdGxOff=0;
    mReport.Stage=7;mReport.ReadyBeforeEbs=0;
    mReport.PostEbsPersistenceProven=0;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI G290GpuPowerEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_ACPI_TABLE_PROTOCOL *acpi=NULL;EFI_STATUS s,report;UINTN key;
    (VOID)Image;(VOID)SystemTable;
    if(mAttempted) return EFI_ALREADY_STARTED;mAttempted=TRUE;
    ZeroMem(&mReport,sizeof(mReport));ZeroMem(&mContext,sizeof(mContext));ZeroMem(&mHub,sizeof(mHub));ZeroMem(&mExternal,sizeof(mExternal));
    mExternal.Header.Signature=G366_EXTERNAL_SIGNATURE;mExternal.Header.Length=sizeof(mExternal);
    mExternal.Header.Revision=1;CopyMem(mExternal.Header.OemId,"OPEN  ",6);
    mExternal.Header.OemTableId=SIGNATURE_64('G','3','6','6','E','X','T',' ');
    mExternal.Header.OemRevision=1;mExternal.Header.CreatorId=SIGNATURE_32('O','P','E','N');
    mExternal.Header.CreatorRevision=1;mExternal.Version=1;mExternal.Status=EFI_NOT_READY;
    mExternal.VotePa=0x00152000;mExternal.BcrPa=0x00171000;mExternal.ClockId=MAX_UINTN;
    mExternal.GetIdStatus=EFI_NOT_READY;mExternal.EnableStatus=EFI_NOT_READY;mExternal.QueryStatus=EFI_NOT_READY;
    mExternal.Enabled=MAX_UINT32;mExternal.VoteBefore=MAX_UINT32;mExternal.VoteAfter=MAX_UINT32;
    mExternal.BcrBefore=MAX_UINT32;mExternal.BcrAfter=MAX_UINT32;
    mHub.Header.Signature=G335_HUB_SIGNATURE;mHub.Header.Length=sizeof(mHub);
    mHub.Header.Revision=1;CopyMem(mHub.Header.OemId,"OPEN  ",6);
    mHub.Header.OemTableId=SIGNATURE_64('G','3','5','9','H','U','B',' ');
    mHub.Header.OemRevision=2;mHub.Header.CreatorId=SIGNATURE_32('O','P','E','N');
    mHub.Header.CreatorRevision=2;mHub.Version=2;mHub.Status=EFI_NOT_READY;
    mHub.ClockId=MAX_UINTN;mHub.RequestedHz=200000000;mHub.ReturnedHz=MAX_UINT32;
    mHub.GetIdStatus=EFI_NOT_READY;mHub.SetHzStatus=EFI_NOT_READY;
    mHub.EnableStatus=EFI_NOT_READY;mHub.QueryStatus=EFI_NOT_READY;mHub.Enabled=MAX_UINT32;
    mHub.FinalQueryStatus=EFI_NOT_READY;mHub.FinalEnabled=MAX_UINT32;
    mHub.RawBefore=MAX_UINT32;mHub.RawAfter=MAX_UINT32;
    mContext.Header.Signature=G335_CX_SIGNATURE;mContext.Header.Length=sizeof(mContext);
    mContext.Header.Revision=1;CopyMem(mContext.Header.OemId,"OPEN  ",6);
    mContext.Header.OemTableId=SIGNATURE_64('G','3','3','5','C','X',' ',' ');
    mContext.Header.OemRevision=1;mContext.Header.CreatorId=SIGNATURE_32('O','P','E','N');
    mContext.Header.CreatorRevision=1;mContext.Version=G335_CX_VERSION;
    for(UINTN j=0;j<4;j++)mContext.Address[j]=mContextPa[j];
    mReport.Header.Signature=G290_POWER_SIGNATURE;mReport.Header.Length=sizeof(mReport);
    mReport.Header.Revision=1;CopyMem(mReport.Header.OemId,"OPEN  ",6);
    mReport.Header.OemTableId=SIGNATURE_64('G','P','U','0','2','9','0',' ');
    mReport.Header.OemRevision=3;mReport.Header.CreatorId=SIGNATURE_32('O','P','E','N');
    mReport.Header.CreatorRevision=3;mReport.Version=G290_POWER_VERSION;
    for(UINTN i=0;i<G290_GATES;i++) mReport.Gate[i].Pa=mPa[i];
    ZeroMem(&mRoot,sizeof(mRoot));
    mRoot.Header=mHub.Header;mRoot.Header.Signature=SIGNATURE_32('O','G','R','C');
    mRoot.Header.Length=sizeof(mRoot);mRoot.Header.OemTableId=SIGNATURE_64('G','4','1','6','R','O','O','T');
    mRoot.Header.OemRevision=1;mRoot.Header.CreatorRevision=1;
    mRoot.Version=1;mRoot.Status=EFI_NOT_READY;
    mRoot.CmdPa=0x03d993ec;mRoot.CfgPa=0x03d993f0;
    ZeroMem(&mPll,sizeof(mPll));
    mPll.Header.Revision=1;CopyMem(mPll.Header.OemId,"OPEN  ",6);
    mPll.Header.OemRevision=1;mPll.Header.CreatorId=SIGNATURE_32('O','P','E','N');
    mPll.Header.CreatorRevision=1;
    mPll.Header.Signature=SIGNATURE_32('O','G','P','L');mPll.Header.Length=sizeof(mPll);
    mPll.Header.OemTableId=SIGNATURE_64('G','4','0','0','G','P','L','L');
    mPll.Version=1;mPll.Status=EFI_NOT_READY;
    for(UINTN j=0;j<6;j++) mPll.Pa[j]=mPllPa[j];
    ZeroMem(&mProxy,sizeof(mProxy));
    mProxy.Header.Signature=SIGNATURE_32('O','G','P','V');mProxy.Header.Length=sizeof(mProxy);
    mProxy.Header.Revision=1;CopyMem(mProxy.Header.OemId,"OPEN  ",6);
    mProxy.Header.OemTableId=SIGNATURE_64('G','4','1','6','P','R','X','Y');
    mProxy.Header.OemRevision=1;mProxy.Header.CreatorId=SIGNATURE_32('O','P','E','N');
    mProxy.Header.CreatorRevision=1;mProxy.Version=1;mProxy.Status=EFI_NOT_READY;
    mProxy.Requested=G416_PROXY_VLVL;mProxy.ClientType=0x40;
    for(UINTN i=0;i<3;i++) {
     mProxy.Before[i]=MAX_UINT32;mProxy.After[i]=MAX_UINT32;mProxy.Final[i]=MAX_UINT32;
     mProxy.AvailableResult[i]=MAX_UINT32;
     mProxy.AvailableStatus[i]=EFI_NOT_READY;mProxy.CreateStatus[i]=EFI_NOT_READY;
     mProxy.RequestStatus[i]=EFI_NOT_READY;mProxy.BeforeQueryStatus[i]=EFI_NOT_READY;
     mProxy.AfterQueryStatus[i]=EFI_NOT_READY;mProxy.FinalQueryStatus[i]=EFI_NOT_READY;
    }
    ZeroMem(&mDomain,sizeof(mDomain));
    CopyMem(&mDomain.Header,&mProxy.Header,sizeof(mDomain.Header));mDomain.Header.Signature=SIGNATURE_32('O','G','D','L');
    mDomain.Header.Length=sizeof(mDomain);mDomain.Header.OemTableId=SIGNATURE_64('G','5','0','7','D','O','M','N');
    mDomain.Version=1;mDomain.Status=EFI_NOT_READY;mDomain.DomainId=MAX_UINTN;
    mDomain.LocateStatus=EFI_NOT_READY;mDomain.GetIdStatus=EFI_NOT_READY;mDomain.EnableStatus=EFI_NOT_READY;
    ZeroMem(&mGx,sizeof(mGx));CopyMem(&mGx.Header,&mProxy.Header,sizeof(mGx.Header));
    mGx.Header.Signature=SIGNATURE_32('O','G','X','P');mGx.Header.Length=sizeof(mGx);mGx.Version=1;
    ZeroMem(&mR721,sizeof(mR721));CopyMem(&mR721.Header,&mProxy.Header,sizeof(mR721.Header));
    mR721.Header.Signature=SIGNATURE_32('O','G','R','7');
    mR721.Header.OemTableId=SIGNATURE_64('G','7','2','1','R','O','O','T');
    mR721.Header.Length=sizeof(mR721);mR721.Version=1;mR721.Status=EFI_NOT_READY;
    G530Init();
    s=Prepare();mReport.Status=s;
    G530_REPORT*lease=G530Report();lease->Header.Checksum=0;
    lease->Header.Checksum=CalculateCheckSum8((UINT8*)lease,sizeof(*lease));
    mGx.Stage=mReport.Stage;mGx.Status=s;mGx.Header.Checksum=CalculateCheckSum8((UINT8*)&mGx,sizeof(mGx));
    mDomain.Header.Checksum=0;mDomain.Header.Checksum=CalculateCheckSum8((UINT8*)&mDomain,sizeof(mDomain));
    mProxy.Header.Checksum=CalculateCheckSum8((UINT8*)&mProxy,sizeof(mProxy));
    mPll.Header.Checksum=CalculateCheckSum8((UINT8*)&mPll,sizeof(mPll));
    mRoot.Header.Checksum=CalculateCheckSum8((UINT8*)&mRoot,sizeof(mRoot));
    mContext.PowerStage=mReport.Stage;mContext.PowerStatus=mReport.Status;
    mHub.Header.Checksum=CalculateCheckSum8((UINT8*)&mHub,sizeof(mHub));
    mExternal.Header.Checksum=CalculateCheckSum8((UINT8*)&mExternal,sizeof(mExternal));
    mContext.Header.Checksum=CalculateCheckSum8((UINT8*)&mContext,sizeof(mContext));
    mReport.Header.Checksum=CalculateCheckSum8((UINT8*)&mReport,sizeof(mReport));
    report=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID**)&acpi);
    if(EFI_ERROR(report)) {DEBUG((DEBUG_ERROR,"G290 report protocol failure %r; image/votes retained\n",report));return EFI_SUCCESS;}
    /* Optional DDR report is independent of all existing GPU report results. */
    report=acpi->InstallAcpiTable(acpi,&mGx,sizeof(mGx),&key);
    if(report!=EFI_SUCCESS) DEBUG((DEBUG_ERROR,"G467 DDR report install failed %r\n",report));
    report=acpi->InstallAcpiTable(acpi,lease,sizeof(*lease),&key);
    if(report!=EFI_SUCCESS) DEBUG((DEBUG_ERROR,"G530 lease report install failed %r\n",report));

    report=acpi->InstallAcpiTable(acpi,&mDomain,sizeof(mDomain),&key);
    if(report!=EFI_SUCCESS) DEBUG((DEBUG_ERROR,"G507 domain report install failed %r\n",report));
    report=acpi->InstallAcpiTable(acpi,&mReport,sizeof(mReport),&key);
    if(EFI_ERROR(report)) {DEBUG((DEBUG_ERROR,"G290 report install failure %r; image/votes retained\n",report));return EFI_SUCCESS;}
    /* Passive companion table: no change to OGPRv3 admission or GPU0 gate. */
    report=acpi->InstallAcpiTable(acpi,&mContext,sizeof(mContext),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G335 OGCX install failure %r\n",report));
    report=acpi->InstallAcpiTable(acpi,&mHub,sizeof(mHub),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G335 OGHU install failure %r\n",report));
    report=acpi->InstallAcpiTable(acpi,&mExternal,sizeof(mExternal),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G366 OGEV install failure %r\n",report));
    report=acpi->InstallAcpiTable(acpi,&mRoot,sizeof(mRoot),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G416 OGRC install failure %r\n",report));
    report=acpi->InstallAcpiTable(acpi,&mPll,sizeof(mPll),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G400 OGPL install failure %r\n",report));
    report=acpi->InstallAcpiTable(acpi,&mProxy,sizeof(mProxy),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G416 OGPV install failure %r\n",report));
    for(UINTN t2=0;t2<9;t2++)mR721.GxDscr[t2]=mG727Trail[t2<1?0:(t2+2)];
    mR721.GxDscr[8]=mG727Trail[11];mR721.GxFlags=mG727Trail[12];
    mR721.GxHwCtl[0]=mG727Trail[1];mR721.GxHwCtl[1]=mG727Trail[2];
    mR721.Header.Checksum=0;mR721.Header.Checksum=CalculateCheckSum8((UINT8*)&mR721,sizeof(mR721));
    report=acpi->InstallAcpiTable(acpi,&mR721,sizeof(mR721),&key);
    if(EFI_ERROR(report)) DEBUG((DEBUG_ERROR,"G721 OGR7 install failure %r\n",report));
    /* Keep image and all partial provider clients resident until reset.
     * No SSDT/GPU0/ID/DDR publication, no SMMU or GMU execution path. */
    return EFI_SUCCESS;
}
