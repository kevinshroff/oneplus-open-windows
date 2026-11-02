/* Actual v5 provider body, host services/types; never Windows ABI proof. */
#include <assert.h>
#include <stdio.h>
#include "win_host.h"
typedef int32_t LONG;typedef uint64_t ULONG64;typedef void*PKTHREAD;
#define OSM_ACTIVE 2
#define GMC_HELD 2
#define CGH_RESET_QUIESCENT 6
#define OLB_PROGRAM_PINNED 3
static void*thread=(void*)0x1234;
#define PsGetCurrentThread() thread
static LONG InterlockedCompareExchange(volatile LONG*p,LONG a,LONG b){LONG v=*p;if(v==b)*p=a;return v;}
static SIZE_T RtlCompareMemory(const void*a,const void*b,SIZE_T n){SIZE_T i=0;while(i<n&&((const char*)a)[i]==((const char*)b)[i])i++;return i;}
typedef struct {void*Pdo,*HeldThread;uint64_t Generation;volatile LONG Inhibit;}LIFE;
typedef struct{LIFE*Life;int BootCommitted,ScopeHeld,Poisoned;void*Thread;uint64_t Generation,Serial;struct{int reset_mode,state,owned,attempted;uint64_t serial;}Hold;struct{struct{struct{void*Context;}Interface;}Api;uint64_t Token;}Clock;}CGH_NATIVE;
typedef struct{int Referenced,ProgramPinned;void*Fdo;CGH_NATIVE*Hold;uint64_t Id,Generation,StopSerial;}OLB_NATIVE;
typedef struct{uint64_t Id,Generation,StopSerial;int State;unsigned Bank,Asid,Slot;}OLB_CLAIM;
typedef struct{uint64_t Id;struct{void*Context,*Pdo;uint64_t Generation;}Client;}OSM_CLIENT_SLOT;
typedef struct {OLB_NATIVE*Bank;uint64_t Generation;int GrantsValid;void*Map[2],*Interrupt[2];unsigned KnownMask,UncertainMask,Retain,Connecting;volatile LONG Armed;struct{volatile LONG Fatal;}Journal;}OF_OWNER;
typedef struct{uint64_t Token,ProviderGeneration;CM_RESOURCE_LIST Grant;}OPEN_NS_SCOPE;
typedef struct{int Started,Removing,Faulted,D0Ref,StopPending,RemovePending;uint64_t Generation,NsToken,NsGeneration;void*NsThread,*NsTag,*NsFault;OLB_NATIVE*NsBank;volatile LONG NsRevoked;OF_OWNER Fault;CM_PARTIAL_RESOURCE_DESCRIPTOR NsGrant;struct{int state;uint64_t generation;unsigned refs;}Lease;unsigned Clients;struct{int state;uint64_t generation;unsigned refs;}Gmu;unsigned GmuClients;OSM_CLIENT_SLOT GmuSlots[8];struct{uint64_t Generation;OLB_CLAIM Claim[20];}Banks;int Granted[1];void*Map[1];unsigned BankClaims;void*Fdo,*LockThread;}OSM_CONTEXT;
static int locks,race;
static void BrokerLock(OSM_CONTEXT*p){assert(!locks);locks++;p->LockThread=thread;if(race)p->NsRevoked=1;}
static void BrokerUnlock(OSM_CONTEXT*p){assert(locks==1);locks--;p->LockThread=0;}
static int Frame(OSM_CONTEXT*p,uint64_t g){return p->LockThread==thread&&p->Started&&!p->Removing&&!p->Faulted&&p->Generation==g?0:-1;}
static int FaultBinding(OSM_CONTEXT*p,OLB_NATIVE*b){return b&&b->Referenced&&b->Fdo==p->Fdo&&b->Hold&&b->Id&&p->BankClaims==1;}
#include "provider_fast.inc"
static OSM_CONTEXT p;static OLB_NATIVE b;static CGH_NATIVE h;static LIFE life;static OPEN_NS_SCOPE scope;static int tag;
static void setup(void){memset(&p,0,sizeof(p));memset(&b,0,sizeof(b));memset(&h,0,sizeof(h));memset(&life,0,sizeof(life));memset(&scope,0,sizeof(scope));race=0;locks=0;p.Started=p.D0Ref=1;p.Granted[0]=1;p.Map[0]=(void*)1;p.Banks.Generation=1;p.Generation=p.NsGeneration=1;p.NsToken=scope.Token=8;scope.ProviderGeneration=1;p.NsThread=thread;p.NsTag=&tag;p.NsBank=&b;p.NsFault=&p.Fault;p.BankClaims=1;p.Fdo=(void*)1;b.Referenced=b.ProgramPinned=1;b.Fdo=p.Fdo;b.Hold=&h;b.Id=4;b.Generation=1;b.StopSerial=7;h.Life=&life;h.ScopeHeld=1;h.Thread=life.HeldThread=thread;h.Generation=life.Generation=1;h.Serial=h.Hold.serial=7;h.Hold.reset_mode=1;h.Hold.state=CGH_RESET_QUIESCENT;h.Clock.Api.Interface.Context=&p;h.Clock.Token=9;life.Pdo=(void*)2;
 p.Lease.state=OSM_ACTIVE;p.Lease.generation=1;p.Clients=1;p.Lease.refs=2;p.Gmu.state=GMC_HELD;p.Gmu.generation=1;p.GmuClients=p.Gmu.refs=1;
 p.Fault.Bank=&b;p.Fault.Generation=1;p.Fault.GrantsValid=1;p.Fault.Map[0]=p.Fault.Map[1]=p.Fault.Interrupt[0]=p.Fault.Interrupt[1]=(void*)1;p.Fault.KnownMask=3;p.Fault.Armed=1;
 p.GmuSlots[0].Id=9;p.GmuSlots[0].Client.Context=&h;p.GmuSlots[0].Client.Pdo=life.Pdo;p.GmuSlots[0].Client.Generation=1;p.Banks.Claim[0]=(OLB_CLAIM){4,1,7,OLB_PROGRAM_PINNED,2,2,0};scope.Grant.Count=scope.Grant.List[0].PartialResourceList.Count=1;}
static NTSTATUS check(void){NTSTATUS s=NsCheckFastApi(&p,&b,&p.Fault,&tag,&scope);assert(!locks);return s;}
#define REJECT(change) do{setup();change;assert(check()!=STATUS_SUCCESS);cases++;}while(0)
int main(void){unsigned cases=0;setup();assert(check()==STATUS_SUCCESS);cases++;
 REJECT(p.Granted[0]=0);REJECT(p.Banks.Generation++);REJECT(p.Map[0]=0);REJECT(p.NsRevoked=1);REJECT(p.Fault.Journal.Fatal=1);REJECT(p.Fault.Armed=0);REJECT(race=1);REJECT(p.Started=0);REJECT(p.D0Ref=0);REJECT(p.StopPending=1);REJECT(p.NsThread=0);REJECT(scope.Token++);REJECT(scope.ProviderGeneration++);REJECT(p.NsTag=0);REJECT(scope.Grant.Count=0);REJECT(scope.Grant.List[0].PartialResourceList.PartialDescriptors[0].Type=3);REJECT(b.ProgramPinned=0);REJECT(b.Generation++);REJECT(life.Inhibit=1);REJECT(h.BootCommitted=1);REJECT(h.Clock.Token++);REJECT(p.GmuSlots[1]=p.GmuSlots[0]);REJECT(p.Lease.refs++);REJECT(p.Gmu.refs++);REJECT(p.Fault.UncertainMask=1);REJECT(p.Fault.KnownMask=1);REJECT(p.Fault.Retain=1);REJECT(p.Fault.Connecting=1);REJECT(p.Fault.Map[0]=0);REJECT(p.Fault.Interrupt[1]=0);REJECT(p.Banks.Claim[0].Asid=3);REJECT(p.Banks.Claim[0].Slot=1);REJECT(p.Banks.Claim[0].StopSerial++);
 printf("PASS %u actual provider software-only cases; revoke/fatal/disarm/token/thread/claim/clockref/faultledger refuse; no MMIO implementation linked\n",cases);return 0;}
