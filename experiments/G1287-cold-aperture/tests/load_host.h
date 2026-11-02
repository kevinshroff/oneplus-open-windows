/* Host type/service fixture only. No Windows ABI or hardware proof. */
#pragma once
#include "win_host.h"
#include "g190_backend.h"
#include "g321_plan.h"
typedef int32_t LONG;typedef void*PETHREAD;
#define OAS_ACTIVE 3
#define OSMA_ACTIVE 3
#define OSMI_BUILT 1
#define CGH_RESET_QUIESCENT 6
#define _ARM64_BARRIER_OSHLD 1
#define _ARM64_BARRIER_OSHST 2
#define __dmb(x) ((void)(x))
#undef __dsb
#define __dsb(x) ((void)(x))
static void*CurrentThread=(void*)0x1234;
#define PsGetCurrentThread() CurrentThread
static LONG InterlockedCompareExchange(volatile LONG*p,LONG a,LONG b){LONG v=*p;if(v==b)*p=a;return v;}
typedef struct {void*Pdo;int Bound;unsigned MappedMask;}G482_BINDING;
typedef struct {void*Pdo,*HeldThread;uint64_t Generation;int StartObserved,OsD0Candidate,Removed;volatile LONG Inhibit;G482_BINDING*Io;}G515_LIFE;
typedef struct {G515_LIFE*Life;void*Thread;uint64_t Generation,Serial;int ScopeHeld,Poisoned,BootCommitted;G482_BINDING*Io;struct{int Bound;uint64_t Token;}Clock;struct{int reset_mode,state,owned,attempted,deferred;unsigned before_halt;uint64_t serial;}Hold;}CGH_NATIVE;
typedef struct {uint64_t Generation;int Poisoned,Disabled,References;struct{int Phase;struct{uint64_t ttbr0;}Image;}Session;struct{int State;unsigned PoolOrigin;struct{uint64_t table_physical;}Config;}Tables;}TABLES;
typedef struct {int Bound;struct{struct{void*Context;}Interface;NTSTATUS(*CheckNsFast)(void*,void*,void*,void*,const void*);}Api;int Native;}BANK_CLIENT;
typedef struct {int State,ColdConsumed;void*OperationThread;CGH_NATIVE*Hold;struct{uint64_t Token,ProviderGeneration;}Scope;uint64_t ProviderGeneration,AllocationGeneration;BANK_CLIENT*Bank;void*Fault;TABLES*Tables;struct{TABLES*Tables;}Native;unsigned BankIndex;}OAS_BOOTSTRAP;
typedef struct G321_RUNTIME {struct{void*Cookie;}Owner;struct{void*Hal;}Role;G482_BINDING*Io;uint64_t Generation,StopSerial;struct{unsigned Stage;}Board;volatile LONG Cancelled;int Closed,Poisoned,Prepared,Attempted,MastersMayRun;g190_backend Core;g321_plan Plan;struct{void*Cpu;int Mapped;}Buffer[16];ULONG LoadWordsLeft,LoadRegion,LoadNextOffset,LoadWrite;}G321_RUNTIME;
typedef struct {G321_RUNTIME*Gmu;G482_BINDING Io;void*Pdo,*OperationThread;CGH_NATIVE Hold;volatile LONG Revoked;G515_LIFE Life;int Started,D0,Removing,StopPending,RemovePending;OAS_BOOTSTRAP*Active;}OGO_CONTEXT;
NTSTATUS OasCurrentRuntime(OAS_BOOTSTRAP*);
NTSTATUS G482CoreRead(G482_BINDING*,ULONG,PULONG);NTSTATUS G482CoreWrite(G482_BINDING*,ULONG,ULONG);
NTSTATUS G482TcmRead(G482_BINDING*,ULONG,ULONG,PULONG);NTSTATUS G482TcmWrite(G482_BINDING*,ULONG,ULONG,ULONG);
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG*);
