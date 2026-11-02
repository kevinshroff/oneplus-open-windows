/* SPDX-License-Identifier: MIT -- exact Open GMU SID5 local NS reservations. */
#ifndef OPEN_LOCAL_BANK_H
#define OPEN_LOCAL_BANK_H
#include "open_smmu_handoff.h"
enum olb_state {OLB_FREE,OLB_RESERVED,OLB_QUALIFIED,OLB_PROGRAM_PINNED,OLB_RETAINED};
enum olb_status {OLB_OK,OLB_ARGUMENT,OLB_CURRENT,OLB_PROFILE,OLB_FULL,OLB_BUSY,OLB_IO_ERROR,OLB_UNSTABLE,OLB_TOKEN};
typedef struct {uint64_t Id,Generation,StopSerial;unsigned Bank,Asid,Slot;enum olb_state State;uint32_t Sctlr;OSH_SNAPSHOT Globals;}OLB_CLAIM;
typedef struct {uint64_t Generation,Sequence;uint32_t BankMask,SlotMask;OLB_CLAIM Claim[20];}OLB_OWNER;
/* All operations serialized by actual MMU1 owner. read is restricted to one
 * tentative candidate's NS SCTLR, not a scan of arbitrary/protected banks.
 * current rechecks actual D0 and continuously-held physical-stop producer. */
typedef struct {void *Context;int(*current)(void*,uint64_t,uint64_t);int(*snapshot)(void*,OSH_SNAPSHOT*);int(*read_sctlr)(void*,unsigned,uint32_t*);}OLB_IO;
enum olb_status OlbReserve(OLB_OWNER*,const OLB_IO*,uint64_t,uint64_t,uint64_t*);
enum olb_status OlbQualify(OLB_OWNER*,const OLB_IO*,uint64_t);
enum olb_status OlbCheck(OLB_OWNER*,const OLB_IO*,uint64_t,OLB_CLAIM*);
/* Call only inside actual first-mutation transaction AFTER all aggregate
 * activation proofs pass. Once pinned, ordinary RAM/clock cleanup is refused.
 * No register write or security/table/fault authorization occurs here. */
enum olb_status OlbCheckPinned(OLB_OWNER*,const OLB_IO*,uint64_t,OLB_CLAIM*);
enum olb_status OlbPinProgramming(OLB_OWNER*,const OLB_IO*,uint64_t);
enum olb_status OlbReleaseUnpublished(OLB_OWNER*,const OLB_IO*,uint64_t);
#endif
