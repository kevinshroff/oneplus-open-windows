#include "gpu_user_bank.h"
#include <string.h>
static enum olb_status capture(const OLB_IO*i,uint64_t g,uint64_t serial,OSH_SNAPSHOT*out){OSH_SNAPSHOT b;OSH_REPORT r;if(!i||!i->current||!i->snapshot||!i->read_sctlr)return OLB_ARGUMENT;if(i->current(i->Context,g,serial))return OLB_CURRENT;if(i->snapshot(i->Context,out)||i->snapshot(i->Context,&b))return OLB_IO_ERROR;return OshAnalyze(out,&b,&r)==OSH_COLD_FAULT_DEFAULT?OLB_OK:OLB_PROFILE;}
enum olb_status OguReserve(OGU_BANK*b,const OLB_IO*i,uint64_t g,uint64_t serial,unsigned gmuSlot,uint64_t id){
 if(!b||b->Id||!id||!g||!serial||gmuSlot>=24)return OLB_ARGUMENT;
 OSH_SNAPSHOT s;enum olb_status st=capture(i,g,serial,&s);if(st)return st;
 /* Exact first cold allocator: choose unused slot distinct from GMU, and do
  * not interpret the IORT range or donor CB list as permission. */
 unsigned slot=gmuSlot?0:1;uint32_t a,v;
 if(i->read_sctlr(i->Context,0,&a)||i->read_sctlr(i->Context,0,&v)||a==UINT32_MAX||a!=v)return OLB_IO_ERROR;
 if(v&1u)return OLB_BUSY;
 OSH_SNAPSHOT after;st=capture(i,g,serial,&after);if(st)return st;if(memcmp(&s,&after,sizeof(s)))return OLB_UNSTABLE;
 *b=(OGU_BANK){.Id=id,.Generation=g,.Serial=serial,.Slot=slot,.Sctlr=v,.Cold=s,.Qualified=1};return OLB_OK;
}
enum olb_status OguCheckCold(OGU_BANK*b,const OLB_IO*i){if(!b||!b->Id||!b->Qualified||b->Retained)return OLB_TOKEN;OSH_SNAPSHOT s;enum olb_status st=capture(i,b->Generation,b->Serial,&s);if(st)return st;if(memcmp(&s,&b->Cold,sizeof(s)))return OLB_UNSTABLE;uint32_t v;if(i->read_sctlr(i->Context,0,&v)||v==UINT32_MAX)return OLB_IO_ERROR;return v==b->Sctlr&&!(v&1u)?OLB_OK:OLB_BUSY;}
