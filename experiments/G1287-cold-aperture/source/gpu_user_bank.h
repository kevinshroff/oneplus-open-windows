/* Exact Open gfx3d_user SID0 -> CB0. Never LPAC1 or secureSID2. */
#ifndef GPU_USER_BANK_H
#define GPU_USER_BANK_H
#include "local_bank.h"
typedef struct {uint64_t Id,Generation,Serial;unsigned Slot;uint32_t Sctlr;OSH_SNAPSHOT Cold;unsigned Qualified,Retained,Programming,Active;uint64_t Root;OSH_SNAPSHOT After;}OGU_BANK;
enum olb_status OguReserve(OGU_BANK*,const OLB_IO*,uint64_t,uint64_t,unsigned GmuSlot,uint64_t Id);
enum olb_status OguCheckCold(OGU_BANK*,const OLB_IO*);
#endif
