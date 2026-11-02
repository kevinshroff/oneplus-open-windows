#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef size_t SIZE_T;typedef unsigned char UCHAR,*PUCHAR,BOOLEAN;typedef uint32_t*PULONG;typedef uint64_t*PULONGLONG;typedef int NTSTATUS;
#define TRUE 1
#define FALSE 0
#define NULLISH 0
#define PASSIVE_LEVEL 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_STATE -2
#define STATUS_DEVICE_DATA_ERROR -3
#define STATUS_NOT_SUPPORTED -4
#define STATUS_DEVICE_BUSY -5
#define MAXULONG UINT32_MAX
#define G190_OK 0
#define MDL_PAGES_LOCKED 1
#define G433_SQE_FILE_BYTES 76724
#define READ_REGISTER_ULONG(p) Read32(p)
#define READ_REGISTER_ULONG64(p) Read64(p)
#define RtlZeroMemory(p,n) memset(p,0,n)
typedef struct {ULONG MdlFlags,bytes,offset;ULONGLONG pfn[19];} MDL;
typedef struct {MDL*Mdl;void*Cpu;} G321_BUFFER;
typedef struct {int held,released,poisoned,freq_acked,oob_may_be_held,status;void*backend;ULONGLONG generation,epoch,stop_serial;int attempted;}g440_gpu_power;
typedef struct {ULONGLONG Smr[25],S2cr[25];ULONG Nscr0,Nsacr;} SNAP;
typedef struct {struct {int stage,attempted;}Core;g440_gpu_power Power;int MastersMayRun,Poisoned,Closed,Prepared,RunAttempted;ULONGLONG Generation,StopSerial;struct{SIZE_T Bytes[4];}Layout;G321_BUFFER Buffer[4];}RUN;
typedef struct {RUN Run;struct {int ActivationQualified;struct{ULONGLONG root_physical;}Tables;}Tables;int Scope,InitialOff,Published,FirstUseConsumed,Phase,Writes;BOOLEAN WitnessAttempted,Retain;void*Smmu;UCHAR*SqeInput;SNAP After;}G982_CP;
typedef struct {struct{struct{SIZE_T register_bytes;}Io;void*Base;}Native;void*OperationThread;}ACTIVE;
typedef struct {struct{ULONGLONG epoch;}Core;ULONGLONG Generation;}GMU;
typedef struct {G982_CP*Cp;struct{ULONGLONG Generation,Serial;int BootCommitted;}Hold;GMU*Gmu;ACTIVE*Active;ULONGLONG RunId;int Io;}OGO_CONTEXT;
static int irql,current_fail,reads,fail_read,corrupt_read,flip_pass,logs,revoke_after,physical_delta;static ULONG gx_value,ahb_value;static UCHAR*regbase;static ULONGLONG*pfns;static UCHAR*bo;
static int KeGetCurrentIrql(void){return irql;}
static void*PsGetCurrentThread(void){return(void*)1;}
static NTSTATUS G482CoreRead(void*io,ULONG off,ULONG*out){(void)io;*out=off==0x14340?gx_value:ahb_value;return 0;}
static NTSTATUS OgoCpCurrent(OGO_CONTEXT*p){(void)p;return current_fail||(revoke_after&&reads>=revoke_after)?-1:0;}
static ULONG MmGetMdlByteOffset(MDL*m){return m->offset;}static ULONG MmGetMdlByteCount(MDL*m){return m->bytes;}static ULONGLONG*MmGetMdlPfnArray(MDL*m){return m->pfn;}
typedef struct{ULONGLONG QuadPart;}PA;
static PA MmGetPhysicalAddress(UCHAR*p){return(PA){pfns[(p-bo)/4096]*4096+(ULONGLONG)physical_delta};}
static void LogPrint(const char*f,...){(void)f;logs++;}
static ULONGLONG ReadValue(void*p,ULONG n){ULONGLONG v=0;memcpy(&v,p,n);reads++;if(reads==fail_read)return n==8?UINT64_MAX:UINT32_MAX;if(reads==corrupt_read)v^=1;if(flip_pass&&reads==25)v^=1;return v;}
static ULONG Read32(void*p){return(ULONG)ReadValue(p,4);}static ULONGLONG Read64(void*p){return ReadValue(p,8);}
#include "g1325_witness.h"
/* ACTUAL_FIRST_USE_FRAME inserted by test.py */
#include "actual_first_use.inc"
#include "actual_cold_current.inc"
#include "g1325_witness_native.inc"
static G982_CP cp;static OGO_CONTEXT owner;static ACTIVE active;static GMU gmu;static MDL mdl;static UCHAR regs[0x40000],bytes[0x13000],input[G433_SQE_FILE_BYTES];
static void setup(void){
 memset(&cp,0,sizeof(cp));memset(&owner,0,sizeof(owner));memset(&active,0,sizeof(active));memset(&gmu,0,sizeof(gmu));memset(&mdl,0,sizeof(mdl));memset(regs,0,sizeof(regs));memset(bytes,0,sizeof(bytes));
 irql=current_fail=reads=fail_read=corrupt_read=flip_pass=logs=revoke_after=physical_delta=0;gx_value=ahb_value=0;owner.Cp=&cp;active.OperationThread=PsGetCurrentThread();owner.Active=&active;owner.Gmu=&gmu;owner.Hold.Generation=owner.Hold.Serial=1;owner.Hold.BootCommitted=1;gmu.Generation=1;gmu.Core.epoch=1;
 cp.Scope=cp.InitialOff=cp.Published=cp.Run.Prepared=cp.Tables.ActivationQualified=cp.Run.RunAttempted=cp.Run.Core.attempted=1;cp.Phase=4;cp.Run.Core.stage=3;cp.Run.Generation=cp.Run.StopSerial=1;
 cp.Run.Power=(g440_gpu_power){1,0,0,1,1,0,&gmu.Core,1,1,1,1};cp.Tables.Tables.root_physical=0x123456789ull;cp.After.Smr[1]=0x80000000;cp.After.S2cr[1]=0x300;cp.After.Nscr0=0x123;cp.After.Nsacr=0x456;
 cp.Smmu=active.Native.Base=regbase=regs;active.Native.Io.register_bytes=sizeof(regs);cp.SqeInput=input;cp.Run.Buffer[2]=(G321_BUFFER){&mdl,bytes};cp.Run.Layout.Bytes[2]=sizeof(bytes);mdl.MdlFlags=1;mdl.bytes=sizeof(bytes);pfns=mdl.pfn;bo=bytes;
 for(unsigned i=0;i<19;i++)mdl.pfn[i]=0x12300+i*3;for(unsigned i=0;i<sizeof(input);i++)input[i]=(UCHAR)i;memcpy(bytes,input+4,sizeof(input)-4);
 G1325_ITEM p[25];G1325Plan(p,cp.Tables.Tables.root_physical,(ULONG)cp.After.Smr[1],(ULONG)cp.After.S2cr[1],cp.After.Nscr0,cp.After.Nsacr);for(unsigned i=0;i<25;i++)memcpy(regs+p[i].Offset,&p[i].Expected,p[i].Width);
}
int main(void){unsigned cases=0;
 setup();assert(Current(&owner)==STATUS_INVALID_DEVICE_STATE);cp.Run.Power.attempted=0;gx_value=1;assert(Current(&owner)==STATUS_SUCCESS);cp.Writes=1;assert(Current(&owner)==STATUS_INVALID_DEVICE_STATE);cases++;
 setup();assert(G1325StopBeforeRelease(&owner)==STATUS_NOT_SUPPORTED);assert(reads==50&&logs==51&&cp.Retain&&!cp.FirstUseConsumed&&!cp.Run.MastersMayRun);assert(G1325StopBeforeRelease(&owner)==STATUS_INVALID_DEVICE_STATE);assert(reads==50);cases++;
 for(int i=1;i<=50;i++){setup();corrupt_read=i;assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);assert(!cp.FirstUseConsumed&&!cp.Run.MastersMayRun);cases++;}
 /* Non-comparison syndrome registers may hold arbitrary historical values;
  * injecting them in one pass must still be reported as unstable. */
 for(int i=1;i<=50;i++){setup();fail_read=i;assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);assert(reads==i);cases++;}
 for(int i=1;i<50;i++){setup();revoke_after=i;assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);assert(reads==i);cases++;}
 setup();physical_delta=4096;assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);cases++;
 setup();bytes[0x12000]=1;assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);cases++;
 setup();input[400]^=1;assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);cases++;
 for(int i=0;i<12;i++){setup();switch(i){case 0:current_fail=1;break;case 1:cp.Run.Power.held=0;break;case 2:cp.Run.Power.freq_acked=0;break;case 3:cp.Run.Power.oob_may_be_held=0;break;case 4:cp.FirstUseConsumed=1;break;case 5:cp.Run.Core.stage=4;break;case 6:active.Native.Io.register_bytes=0;break;case 7:irql=1;break;case 8:cp.Tables.ActivationQualified=0;break;case 9:gx_value=1;break;case 10:ahb_value=1;break;case 11:cp.Run.Power.attempted=0;break;}assert(G1325StopBeforeRelease(&owner)==STATUS_DEVICE_DATA_ERROR);assert(reads==0);cases++;}
 setup();cp.WitnessAttempted=1;ULONGLONG v;assert(G1325Read(&owner,0x20800,8,&v));assert(reads==0);assert(G1325Read(&owner,0x20020,4,&v));cases++;
 printf("{\"cases\":%u,\"native_evidence\":false,\"actual_FirstUseFrame\":true,\"actual_native_adapter\":true}\n",cases);return 0;
}
