/* Bounded initial SID0/CB0 lower39/36 single TTBR0, distinct from GMU SID5.
 * Fixed private CP buffers only; no perprocess switch, TTBR1 or secure SID2.
 * Uses the already-owned NS mapping under the real provider NsMutex interval.
 * No global NSCR0/NSACR/TLBI store or GMU context store is admitted. */
#include "gpu_owner.h"
#include "gpu_cp_native.h"
#include <intrin.h>
#define CB 0x20000u
static NTSTATUS Current(OGO_CONTEXT*p){G982_CP*c=p->Cp;ULONG gx;
 if(!c||!c->InitialOff||c->FirstUseConsumed||c->Writes||c->Run.Power.attempted||!c->Scope||p->Active->OperationThread!=PsGetCurrentThread())return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS s=OgoCpCurrent(p);if(s!=STATUS_SUCCESS)return s;s=G482CoreRead(&p->Io,0x14340,&gx);if(s!=STATUS_SUCCESS)return s;return gx!=MAXULONG&&(gx&1)?STATUS_SUCCESS:STATUS_DEVICE_BUSY;
}
static NTSTATUS Read(OGO_CONTEXT*p,ULONG off,PULONG v){NTSTATUS s=Current(p);if(s!=STATUS_SUCCESS)return s;p->Cp->SmmuReads++;*v=READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Cp->Smmu+off));return *v==MAXULONG?STATUS_DEVICE_DATA_ERROR:STATUS_SUCCESS;}
static NTSTATUS Read64(OGO_CONTEXT*p,ULONG off,PULONGLONG v){NTSTATUS s=Current(p);if(s!=STATUS_SUCCESS)return s;p->Cp->SmmuReads++;*v=READ_REGISTER_ULONG64((PULONGLONG)((PUCHAR)p->Cp->Smmu+off));return *v==MAXULONGLONG?STATUS_DEVICE_DATA_ERROR:STATUS_SUCCESS;}
static NTSTATUS Write(OGO_CONTEXT*p,ULONG off,ULONG v){NTSTATUS s=Current(p);if(s!=STATUS_SUCCESS)return s;ULONG slot=p->GpuUser.Slot;
 BOOLEAN ok=(off==0x800+4*slot&&v==0x80000000u)||(off==0xc00+4*slot&&(v==0x20000||v==0x300))||(off==0x1000&&v==0x1f300)||(off==0x1800&&v==1)||(off==CB&&(v==0||v==0xc00067))||(off==CB+4&&v==0x32b)||(off==CB+0x10&&v==0x38071)||(off==CB+0x30&&v==0x803519)||(off==CB+0x38&&v==0xf404ff44)||(off==CB+0x3c&&v==0xefe4)||(off==CB+0x610&&v==0)||(off==CB+0x7f0&&v==MAXULONG);
 if(!ok)return STATUS_ACCESS_DENIED;p->Cp->Retain=TRUE;p->Cp->SmmuWrites++;WRITE_REGISTER_ULONG((PULONG)((PUCHAR)p->Cp->Smmu+off),v);__dsb(_ARM64_BARRIER_OSH);return STATUS_SUCCESS;
}
static NTSTATUS Write64(OGO_CONTEXT*p,ULONG off,ULONGLONG v){NTSTATUS s=Current(p);if(s!=STATUS_SUCCESS)return s;if(!((off==CB+0x20&&v==p->Cp->Tables.Tables.root_physical)||(off==CB+0x28&&v==0)))return STATUS_ACCESS_DENIED;p->Cp->Retain=TRUE;p->Cp->SmmuWrites++;WRITE_REGISTER_ULONG64((PULONGLONG)((PUCHAR)p->Cp->Smmu+off),v);__dsb(_ARM64_BARRIER_OSH);return STATUS_SUCCESS;}
static NTSTATUS Set(OGO_CONTEXT*p,ULONG off,ULONG v){ULONG got;NTSTATUS s=Write(p,off,v);if(s==STATUS_SUCCESS)s=Read(p,off,&got);return s==STATUS_SUCCESS&&got!=v?STATUS_DEVICE_DATA_ERROR:s;}
static NTSTATUS Set64(OGO_CONTEXT*p,ULONG off,ULONGLONG v){ULONGLONG got;NTSTATUS s=Write64(p,off,v);if(s==STATUS_SUCCESS)s=Read64(p,off,&got);return s==STATUS_SUCCESS&&got!=v?STATUS_DEVICE_DATA_ERROR:s;}
static NTSTATUS Snapshot(OGO_CONTEXT*p,OSH_SNAPSHOT*s){NTSTATUS st;RtlZeroMemory(s,sizeof(*s));const ULONG at[]={0x20,0x24,0x28,0,0x10};PULONG field[]={(PULONG)&s->Id0,(PULONG)&s->Id1,(PULONG)&s->Id2,(PULONG)&s->Nscr0,(PULONG)&s->Nsacr};for(unsigned i=0;i<5;i++){st=Read(p,at[i],field[i]);if(st!=STATUS_SUCCESS)return st;}for(unsigned i=0;i<OSH_SMRS;i++){st=Read(p,0x800+4*i,(PULONG)&s->Smr[i]);if(st!=STATUS_SUCCESS)return st;st=Read(p,0xc00+4*i,(PULONG)&s->S2cr[i]);if(st!=STATUS_SUCCESS)return st;}return STATUS_SUCCESS;}
static NTSTATUS Globals(OGO_CONTEXT*p){OSH_SNAPSHOT a,z;NTSTATUS s=Snapshot(p,&a);if(s==STATUS_SUCCESS)s=Snapshot(p,&z);return s==STATUS_SUCCESS&&(RtlCompareMemory(&a,&p->Cp->Expected,sizeof(a))!=sizeof(a)||RtlCompareMemory(&z,&p->Cp->Expected,sizeof(z))!=sizeof(z))?STATUS_DEVICE_CONFIGURATION_ERROR:s;}
static NTSTATUS Sync(OGO_CONTEXT*p){NTSTATUS s=Write(p,CB+0x610,0);if(s!=STATUS_SUCCESS)return s;s=Write(p,CB+0x7f0,MAXULONG);if(s!=STATUS_SUCCESS)return s;for(unsigned i=0;i<1000;i++){ULONG v;p->Cp->SmmuPolls++;s=Read(p,CB+0x7f4,&v);if(s!=STATUS_SUCCESS)return s;if(!(v&1))return STATUS_SUCCESS;KeStallExecutionProcessor(1);}return STATUS_IO_TIMEOUT;}
#define TRY(x) do{s=(x);if(s!=STATUS_SUCCESS)goto done;}while(0)
NTSTATUS OgoActivateGpu0(OGO_CONTEXT*p){G982_CP*c=p->Cp;NTSTATUS s;ULONG v;OSH_SNAPSHOT again;
 if(!c||!c->Scope||!c->InitialOff||c->Published||p->GpuUser.Bank||p->GpuUser.Sid||p->GpuUser.Asid||p->GpuUser.Slot!=1||!p->Active->Native.Base)return STATUS_INVALID_DEVICE_STATE;
 TRY(OsmiAuditInactive(&c->Tables));c->Smmu=p->Active->Native.Base;
 TRY(Current(p));TRY(Snapshot(p,&c->Before));TRY(Snapshot(p,&again));
 if(RtlCompareMemory(&c->Before,&again,sizeof(again))!=sizeof(again)||RtlCompareMemory(&c->Before,&p->Active->Tables->Session.After,sizeof(again))!=sizeof(again)||c->Before.Id0!=0x4c017e18||c->Before.Id1!=0x40000016||c->Before.Id2!=0x5511||c->Before.Smr[1]||c->Before.S2cr[1]!=0x20000){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 c->Expected=c->Before;TRY(Read(p,CB,&v));if(v&1){s=STATUS_DEVICE_BUSY;goto done;}
 TRY(p->Bank.Api.PinGpuProgramming(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser,&p->Active->Scope,&c->Tables));
 /* Sticky mutation before first store; no rollback/retry/free on failure. */
 for(unsigned i=0;i<4;i++)c->Run.Buffer[i].MapAttempted=TRUE;
 TRY(Set(p,0xc04,0x20000));TRY(Globals(p));TRY(Set(p,CB,0));TRY(Set(p,CB+4,0x32b));TRY(Sync(p));
 TRY(Set(p,0x1800,1));TRY(Set(p,0x1000,0x1f300));TRY(Set(p,CB+0x10,0x38071));TRY(Set(p,CB+0x30,0x803519));TRY(Set64(p,CB+0x20,c->Tables.Tables.root_physical));TRY(Set64(p,CB+0x28,0));TRY(Set(p,CB+0x38,0xf404ff44));TRY(Set(p,CB+0x3c,0xefe4));
 /* FSR.Format[10:9]=2 is generated by owned CBA2R.VA64=1. Require
  * exact AArch64 format with no fault/unknown bits; never clear Format. */
 TRY(Read(p,CB+0x58,&v));if(v!=0x400u){s=STATUS_DEVICE_HARDWARE_ERROR;goto done;}TRY(Sync(p));TRY(Globals(p));TRY(Set(p,CB,0xc00067));TRY(Read(p,CB+0x58,&v));if(v!=0x400u){s=STATUS_DEVICE_HARDWARE_ERROR;goto done;}
 TRY(Set(p,0x804,0x80000000u));c->Expected.Smr[1]=0x80000000u;TRY(Globals(p));TRY(Set(p,0xc04,0x300));c->Expected.S2cr[1]=0x300;TRY(Globals(p));
 TRY(p->Bank.Api.CommitGpuProgramming(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser,&p->Active->Scope,&c->Tables));c->After=c->Expected;
 for(unsigned i=0;i<4;i++){c->Run.Buffer[i].MapAttempted=TRUE;c->Run.Buffer[i].Mapped=TRUE;}s=STATUS_SUCCESS;
done:if(s!=STATUS_SUCCESS&&c->SmmuWrites){c->Tables.State=OSMI_POISONED;c->Run.Poisoned=TRUE;}return s;
}
