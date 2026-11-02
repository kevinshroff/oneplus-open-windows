/* SPDX-License-Identifier: MIT
 * Reconstructed exact shipped ARM64 protocol prefix, NOT a public SDK claim.
 * RpmhDxe SHA8c5db67f...b3343, vtable0xe0f8, version0x10001.
 * No method below takes an EFI This pointer. Argument registers, not inferred
 * decompiler signatures, establish the called Create/Issue ABI.
 */
#ifndef G202_RPMH_ABI_H
#define G202_RPMH_ABI_H
#include <stdint.h>
#include <stddef.h>
typedef uint64_t G202_STATUS;
#define G202_ERR(N) (UINT64_C(0x8000000000000000)|(N))
typedef struct {uint32_t Address,Data;uint8_t Completion,Reserved[3];}G202_COMMAND;
typedef struct {uint32_t Set,Count,DriverScratch;G202_COMMAND Command[16];}G202_COMMAND_SET;
_Static_assert(sizeof(G202_COMMAND)==12,"Actual RPMh command stride");
_Static_assert(offsetof(G202_COMMAND_SET,Command)==12,"Actual command-set header");
_Static_assert(sizeof(G202_COMMAND_SET)==0xcc,"Actual command-set size");
typedef void(*G202_UNUSED)(void);
typedef struct{
 uint64_t Version;
 G202_UNUSED Init; /* Never called: do not reset/reinitialize firmware clients. */
 G202_STATUS(*IsDrvSupported)(uint32_t,uint8_t*);
 G202_STATUS(*GetTcsSize)(uint32_t,uint32_t*);
 G202_STATUS(*CreateHandle)(uint32_t,const char*,uint8_t,void**);
 G202_UNUSED CreateDefault,CreateExplicit,ClearExplicit,RegisterCallback,DeleteHandle,UnknownSlot80;
 G202_STATUS(*ChurnAll)(void*,uint32_t);
 G202_STATUS(*ChurnSingle)(void*,uint32_t);
 G202_UNUSED BarrierAll,BarrierSingle;
 G202_STATUS(*IssueCommandSet)(void*,G202_COMMAND_SET*,uint32_t*);
}G202_RPMH_PROTOCOL;
_Static_assert(offsetof(G202_RPMH_PROTOCOL,CreateHandle)==32,"Actual CreateHandle slot");
_Static_assert(offsetof(G202_RPMH_PROTOCOL,IssueCommandSet)==120,"Actual IssueCommandSet slot");
typedef struct{
 uint64_t Version;
 G202_UNUSED Slot8;
 G202_STATUS(*GetAddress)(void*,const char*,uint32_t*);
}G202_CMDDB_PROTOCOL;
_Static_assert(offsetof(G202_CMDDB_PROTOCOL,GetAddress)==16,"Actual CmdDb QueryAddress slot");
typedef struct{const char*Supply,*Resource;uint32_t Millivolts;}G202_RAIL_SPEC;
extern const G202_RAIL_SPEC G202Rails[6];
typedef struct{G202_STATUS Status;uint32_t Address,Attempted;}G336_CMD_QUERY;
_Static_assert(sizeof(G336_CMD_QUERY)==16,"G336 query diagnostic ABI");
typedef struct{G202_RPMH_PROTOCOL*Rpmh;G202_CMDDB_PROTOCOL*CmdDb;void*Client;uint32_t Address[6],Resolved;G336_CMD_QUERY Trace[7];}G202_RAIL_CALLER;
G202_STATUS G202ResolveRailAddresses(G202_RAIL_CALLER*);
G202_STATUS G202CreateRailClient(G202_RAIL_CALLER*);
G202_STATUS G202BuildRailCommand(const G202_RAIL_CALLER*,uint32_t,uint8_t,G202_COMMAND_SET*);
/* Low-level actual call only. Actual shipped Issue waits without a timeout
 * and caches by resource+DRV, not client. This is not an independently owned
 * rail provider. No implicit physical, aggregation or safe-unwind claim.
 */
G202_STATUS G202IssueRailCommand(G202_RAIL_CALLER*,G202_COMMAND_SET*,uint32_t*);
/* Exact source root reference request; same unbounded/shared-DRV limitations
 * as rail calls. No clka1/RF clock is invented. No off/restore is exposed. */
G202_STATUS G202IssueXoReference(G202_RAIL_CALLER*,uint32_t*Address,uint32_t*RequestId);
#endif
