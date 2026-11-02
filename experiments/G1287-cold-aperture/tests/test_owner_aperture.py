"""CPU actor over actual owner setup + actual once-consume bodies; SMC is a mock."""
from pathlib import Path
import subprocess,json,hashlib
W=Path(__file__).resolve().parents[1];B=W/'tests/aperture-build';B.mkdir(exist_ok=True)
s=(W/'source/owner/bootstrap.c').read_text();body=s[s.index('static NTSTATUS ApertureColdSetup('):s.index('NTSTATUS OgoBootstrap(')]
e=(W/'source/owner/owner_entry.c').read_text();once=e[e.index('BOOLEAN OgoConsumeAperture('):e.index('static NTSTATUS ReadEnable(')]
pre=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "aperture_policy.h"
typedef void VOID;typedef int BOOLEAN;typedef int NTSTATUS;typedef void*PVOID;typedef unsigned ULONG;typedef unsigned long long ULONGLONG;
#define TRUE 1
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_STATE -1
#define STATUS_DEVICE_NOT_READY -2
#define STATUS_UNSUCCESSFUL -3
#define STATUS_NOT_SUPPORTED -4
#define OAS_OPEN 1
#define CGH_RESET_QUIESCENT 6
#define DPFLTR_IHVVIDEO_ID 0
#define DPFLTR_INFO_LEVEL 0
#define DbgPrintEx(...) ((void)0)
typedef struct{unsigned Referenced,Qualified,Sid,Bank,Asid,Slot;ULONGLONG Id,Generation,Serial;}OGU_TOKEN;
typedef struct{PVOID Context;unsigned Attempted,Completed,Transport;NTSTATUS Status;unsigned DispatchKnown;ULONGLONG DispatchStatus,OwnerGeneration,RunId,Generation,Serial,GpuId,GpuGeneration,GpuSerial;OAS_SCM_FRAME Frame;}OAS_COLD_SETUP;
typedef struct{OAS_COLD_SETUP Setup;unsigned State,ColdConsumed;void*OperationThread;struct{ULONGLONG Token;}Scope;}OAS_BOOTSTRAP;
typedef struct{OAS_BOOTSTRAP*Active;unsigned CpInit;void*Gmu,*Cp,*OperationThread;ULONGLONG Generation,RunId;OGU_TOKEN GpuUser;struct{unsigned BootCommitted;ULONGLONG Generation,Serial;struct{unsigned state,reset_mode;}Hold;}Hold;int Revoked;}OGO_CONTEXT;
static int ApertureEnabled,ApertureConsumed,smcs,changeToken,revokeAfter;static ULONGLONG raw;
static void*PsGetCurrentThread(void){return (void*)1;}
static NTSTATUS Recheck(OGO_CONTEXT*p){return p->Revoked?STATUS_DEVICE_NOT_READY:STATUS_SUCCESS;}
static BOOLEAN OgoApertureRequested(void){return ApertureEnabled;}
static int InterlockedCompareExchange(int*p,int n,int old){int was=*p;if(was==old)*p=n;return was;}
static OGO_CONTEXT owner;static OAS_BOOTSTRAP active;
static void G1287SmcSetCp0(OAS_SCM_FRAME*f){smcs++;f->X[0]=raw;f->X[1]=0xabcdef;f->Entries=f->Returns=1;if(changeToken)owner.GpuUser.Id++;if(revokeAfter)owner.Revoked=1;}
'''
post=r'''
static void init(void){memset(&owner,0,sizeof(owner));memset(&active,0,sizeof(active));ApertureEnabled=1;ApertureConsumed=smcs=changeToken=revokeAfter=0;raw=0;owner.Active=&active;owner.CpInit=1;owner.OperationThread=(void*)1;owner.Generation=2;owner.RunId=3;owner.Hold.Generation=4;owner.Hold.Serial=5;owner.Hold.Hold.state=CGH_RESET_QUIESCENT;owner.Hold.Hold.reset_mode=1;owner.GpuUser=(OGU_TOKEN){1,1,0,0,0,1,6,7,8};active.State=OAS_OPEN;active.Scope.Token=9;active.OperationThread=(void*)1;active.Setup=(OAS_COLD_SETUP){.OwnerGeneration=2,.RunId=3,.Generation=4,.Serial=5,.GpuId=6,.GpuGeneration=7,.GpuSerial=8};}
int main(void){int n=0;init();assert(ApertureColdSetup(&owner,&active)==0&&smcs==1&&ApertureConsumed&&active.Setup.Completed&&active.Setup.DispatchKnown&&active.Setup.Transport==1&&active.Setup.Frame.X[1]==0xabcdef);assert(ApertureColdSetup(&owner,&active)!=0&&smcs==1);n+=2;
 for(int i=0;i<6;i++){init();if(i==0)owner.CpInit=0;if(i==1)active.Setup.Generation++;if(i==2)owner.GpuUser.Sid=1;if(i==3)ApertureEnabled=0;if(i==4)ApertureConsumed=1;if(i==5)active.Setup.GpuId++;assert(ApertureColdSetup(&owner,&active)!=0&&smcs==0&&!active.Setup.Attempted);n++;}
 const ULONGLONG errors[]={16,2,3,0xfffffff4ULL,0xfffffffffffffff4ULL};for(unsigned i=0;i<5;i++){init();raw=errors[i];assert(ApertureColdSetup(&owner,&active)!=0&&smcs==1&&active.Setup.Attempted&&!active.Setup.Completed&&active.Setup.Frame.X[0]==raw);assert(active.Setup.DispatchKnown==(raw==16));assert(!OgoConsumeAperture());n++;}
 for(int i=0;i<2;i++){init();if(i==0)changeToken=1;else revokeAfter=1;assert(ApertureColdSetup(&owner,&active)!=0&&smcs==1&&active.Setup.Attempted&&active.Setup.Completed);n++;}
 printf("%d actual owner setup/once cases PASS; monitor calls0\n",n);}
'''
p=B/'owner_actual.c';p.write_text(pre+once+body+post);a=['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=address,undefined','-I'+str(W/'source'),str(p),'-o',str(B/'owner_actor')];q=subprocess.run(a,capture_output=True,text=True);assert q.returncode==0,q.stderr;q=subprocess.run([str(B/'owner_actor')],capture_output=True,text=True);assert q.returncode==0,q.stdout+q.stderr
out={'schema':'g1287-actual-owner-setup-actor/1','result':q.stdout.strip(),'production_body_extracted_without_logic_changes':True,'SMC_is_mock_only':True,'monitor_calls':0,'source_pins':{str(p.relative_to(W)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [W/'source/owner/bootstrap.c',W/'source/owner/owner_entry.c',Path(__file__)]}};(W/'tests/OWNER-APERTURE-RESULT.json').write_text(json.dumps(out,indent=2)+'\n');print(q.stdout,end='')
