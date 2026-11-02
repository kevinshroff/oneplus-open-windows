
#include <assert.h>
#include <stdio.h>
#include "aperture_policy.h"
typedef int NTSTATUS;typedef int BOOLEAN;typedef void* PVOID;
#define PASSIVE_LEVEL 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_STATE -1
#define STATUS_DEVICE_NOT_READY -2
#define NEED 255
#define OAS_OPEN 1
#define OAS_ATTEMPTING 2
#define OAS_ACTIVE 3
#define OAS_RETAINED 4
typedef struct{int dummy;}OSMA_PROOFS;
typedef struct{unsigned Bank,Asid,Slot;}OSMA_REQUEST;
typedef struct OAS_BOOTSTRAP OAS_BOOTSTRAP;
typedef struct{PVOID Context;NTSTATUS(*Run)(PVOID,OAS_BOOTSTRAP*);unsigned Attempted,Completed;NTSTATUS Status;}SETUP;
typedef struct{struct{void*Context;}Interface;NTSTATUS(*PinProgramming)(void*,void*,OSMA_REQUEST*);}API;
typedef struct{API Api;struct{int ProgramPinned;}Native;}BANK;
struct OAS_BOOTSTRAP{int State;struct{void*Base;OSMA_PROOFS Proof;}Native;BANK*Bank;void*Hold;SETUP Setup;NTSTATUS Status;};
static int beginError,aggFailure,aggCount,pinError,actError,endError,callError,callAttempt,callComplete,pins,acts,ends,retains;
static NTSTATUS Begin(OAS_BOOTSTRAP*a){(void)a;return beginError;}
static OSMA_REQUEST Q(OAS_BOOTSTRAP*a){(void)a;return (OSMA_REQUEST){2,2,0};}
static int Aggregate(OAS_BOOTSTRAP*a,OSMA_PROOFS*p,int needs,int sid,unsigned bank,unsigned asid,unsigned slot){(void)a;(void)p;(void)needs;(void)sid;(void)bank;(void)asid;(void)slot;return ++aggCount==aggFailure;}
static NTSTATUS Pin(void*x,void*n,OSMA_REQUEST*q){(void)x;(void)n;(void)q;pins++;return pinError;}
static NTSTATUS OsmaActivateOwnedBinding(void*n){(void)n;acts++;return actError;}
static NTSTATUS End(OAS_BOOTSTRAP*a,NTSTATUS st){ends++;if(endError){a->State=OAS_RETAINED;return endError;}return st;}
static NTSTATUS CghNativeRetainFailure(void*h,NTSTATUS st){(void)h;retains++;return st;}
static NTSTATUS Callback(PVOID x,OAS_BOOTSTRAP*a){(void)x;a->Setup.Attempted=callAttempt;a->Setup.Completed=callComplete;return callError;}
NTSTATUS OasActivate(OAS_BOOTSTRAP*a){if(!a||a->State!=OAS_OPEN||!a->Native.Base)return STATUS_INVALID_DEVICE_STATE;NTSTATUS st=Begin(a);if(st!=STATUS_SUCCESS){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);return a->Status=st;}
 OSMA_REQUEST q=Q(a);if(Aggregate(a,&a->Native.Proof,NEED,5,q.Bank,q.Asid,q.Slot))st=STATUS_DEVICE_NOT_READY;
 /* Setup runs inside this actual cold namespace before any table programming. */
 if(st==STATUS_SUCCESS&&a->Setup.Run){st=a->Setup.Run(a->Setup.Context,a);a->Setup.Status=st;
  if(st==STATUS_SUCCESS&&(!a->Setup.Attempted||!a->Setup.Completed))st=STATUS_INVALID_DEVICE_STATE;
  if(st==STATUS_SUCCESS&&Aggregate(a,&a->Native.Proof,NEED,5,q.Bank,q.Asid,q.Slot))st=STATUS_DEVICE_NOT_READY;
  if(OasSetupRetains(a->Setup.Attempted,st==STATUS_SUCCESS))a->State=OAS_RETAINED;
 }
 if(st==STATUS_SUCCESS){st=a->Bank->Api.PinProgramming(a->Bank->Api.Interface.Context,&a->Bank->Native,&q);if(st==STATUS_SUCCESS){a->State=OAS_ATTEMPTING;st=OsmaActivateOwnedBinding(&a->Native);if(st==STATUS_SUCCESS)a->State=OAS_ACTIVE;else a->State=OAS_RETAINED;}}
 if(OasSetupRetains(a->Setup.Attempted,st==STATUS_SUCCESS))a->State=OAS_RETAINED;
 st=End(a,st);if(st!=STATUS_SUCCESS&&(a->Bank->Native.ProgramPinned||a->Setup.Attempted)){a->State=OAS_RETAINED;(void)CghNativeRetainFailure(a->Hold,st);}return a->Status=st;
}

static void reset(void){beginError=aggFailure=aggCount=pinError=actError=endError=callError=pins=acts=ends=retains=0;callAttempt=callComplete=1;}
static OAS_BOOTSTRAP fresh(BANK*b){return (OAS_BOOTSTRAP){.State=OAS_OPEN,.Native={.Base=(void*)1},.Bank=b};}
int main(void){BANK b={.Api={.PinProgramming=Pin}};OAS_BOOTSTRAP a;int cases=0;
 reset();a=fresh(&b);assert(OasActivate(&a)==0&&a.State==OAS_ACTIVE&&pins==1&&acts==1&&ends==1);cases++;
 reset();a=fresh(&b);a.Setup.Run=Callback;assert(OasActivate(&a)==0&&a.State==OAS_ACTIVE&&aggCount==2&&ends==1);cases++;
 reset();a=fresh(&b);a.Setup.Run=Callback;callAttempt=callComplete=0;callError=-8;assert(OasActivate(&a)!=0&&a.State==OAS_OPEN&&!pins&&!retains&&ends==1);cases++; /* ordinary unattempted cleanup remains possible */
 for(int i=0;i<6;i++){reset();a=fresh(&b);a.Setup.Run=Callback;
 if(i==0)callError=-8;if(i==1)aggFailure=2;if(i==2)pinError=-9;if(i==3)actError=-10;if(i==4)endError=-11;if(i==5)callComplete=0;
 assert(OasActivate(&a)!=0&&a.State==OAS_RETAINED&&retains&&ends==1);if(i<=1)assert(!pins&&!acts);cases++;}
 reset();a=fresh(&b);a.Setup.Run=Callback;aggFailure=1;assert(OasActivate(&a)!=0&&!a.Setup.Attempted&&a.State==OAS_OPEN&&!pins&&ends==1);cases++;
 OAS_SCM_FRAME f={{0},1,1,0};assert(OasScmTransport(&f)==OAS_SCM_TRANSPORT_COMPLETE);cases++;
 const unsigned long long v[]={16,1,2,3,7,0x100000000ULL,0x100000001ULL,0x1fffffff4ULL,0xffffffff00000001ULL};for(unsigned i=0;i<sizeof(v)/sizeof(v[0]);i++){f.X[0]=v[i];assert(OasScmTransport(&f)==OAS_SCM_UNKNOWN&&f.X[0]==v[i]);cases++;}
 const unsigned long long e[]={0xfffffff4ULL,0xfffffffffffffff4ULL,0xffffffffULL,0xffffffffffffffffULL};for(unsigned i=0;i<4;i++){f.X[0]=e[i];assert(OasScmTransport(&f)==OAS_SCM_ERROR);cases++;}
 f=(OAS_SCM_FRAME){{0},3,3,2};assert(OasScmTransport(&f)==OAS_SCM_TRANSPORT_COMPLETE);cases++;f.Returns=0;assert(OasScmTransport(&f)==OAS_SCM_UNKNOWN);cases++;
 printf("%d actual-OasActivate/policy cases PASS; monitor calls0\n",cases);}
