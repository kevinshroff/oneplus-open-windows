#include "local_bank.h"
#include <string.h>
static OLB_CLAIM*find(OLB_OWNER*o,uint64_t id){if(!o||!id)return 0;for(unsigned i=0;i<20;i++)if(o->Claim[i].Id==id&&o->Claim[i].State!=OLB_FREE)return &o->Claim[i];return 0;}
static int args(const OLB_IO*i){return !i||!i->current||!i->snapshot||!i->read_sctlr;}
static enum olb_status capture(const OLB_IO*i,uint64_t g,uint64_t serial,OSH_SNAPSHOT*a){OSH_SNAPSHOT b;OSH_REPORT r;if(i->current(i->Context,g,serial))return OLB_CURRENT;if(i->snapshot(i->Context,a)||i->snapshot(i->Context,&b))return OLB_IO_ERROR;if(OshAnalyze(a,&b,&r)!=OSH_COLD_FAULT_DEFAULT)return OLB_PROFILE;return i->current(i->Context,g,serial)?OLB_CURRENT:OLB_OK;}
static enum olb_status fresh(OLB_OWNER*o,const OLB_IO*i,OLB_CLAIM*c){OSH_SNAPSHOT a;enum olb_status s;if(!o||args(i)||!c||c->Generation!=o->Generation)return OLB_ARGUMENT;if((s=capture(i,c->Generation,c->StopSerial,&a)))return s;return memcmp(&a,&c->Globals,sizeof(a))?OLB_UNSTABLE:OLB_OK;}
enum olb_status OlbReserve(OLB_OWNER*o,const OLB_IO*i,uint64_t g,uint64_t stop,uint64_t*out){
 if(!o||args(i)||!g||!stop||!out)return OLB_ARGUMENT;*out=0;OSH_SNAPSHOT a;enum olb_status s=capture(i,g,stop,&a);if(s)return s;
 if(!o->Generation){o->Generation=g;o->BankMask=3;}
 if(o->Generation!=g||o->Sequence==UINT64_MAX)return OLB_CURRENT;
 if(o->SlotMask)return OLB_BUSY; /* One exclusive SID5 route reservation. */
 unsigned bank,slot,index;for(bank=2;bank<22;bank++)if(!(o->BankMask&(1u<<bank)))break;for(slot=0;slot<24;slot++)if(!(o->SlotMask&(1u<<slot)))break;for(index=0;index<20;index++)if(o->Claim[index].State==OLB_FREE)break;
 if(bank==22||slot==24||index==20)return OLB_FULL;
 OLB_CLAIM*c=&o->Claim[index];memset(c,0,sizeof(*c));c->Id=++o->Sequence;c->Generation=g;c->StopSerial=stop;c->Bank=c->Asid=bank;c->Slot=slot;c->Globals=a;c->State=OLB_RESERVED;o->BankMask|=1u<<bank;o->SlotMask|=1u<<slot;*out=c->Id;return OLB_OK;
}
enum olb_status OlbQualify(OLB_OWNER*o,const OLB_IO*i,uint64_t id){OLB_CLAIM*c=find(o,id);if(!c||c->State!=OLB_RESERVED||args(i))return OLB_TOKEN;enum olb_status s=fresh(o,i,c);if(s)return s;
 uint32_t a,b;if(i->read_sctlr(i->Context,c->Bank,&a)||i->read_sctlr(i->Context,c->Bank,&b)||a==UINT32_MAX||b==UINT32_MAX)return OLB_IO_ERROR;if(a!=b)return OLB_UNSTABLE;if(a&1u)return OLB_BUSY;if((s=fresh(o,i,c)))return s;c->Sctlr=b;c->State=OLB_QUALIFIED;return OLB_OK;}
enum olb_status OlbCheck(OLB_OWNER*o,const OLB_IO*i,uint64_t id,OLB_CLAIM*out){OLB_CLAIM*c=find(o,id);if(!c||!out||c->State!=OLB_QUALIFIED||args(i))return OLB_TOKEN;enum olb_status s=fresh(o,i,c);if(s)return s;uint32_t v;if(i->read_sctlr(i->Context,c->Bank,&v)||v==UINT32_MAX)return OLB_IO_ERROR;if(v!=c->Sctlr||(v&1))return OLB_BUSY;if(i->current(i->Context,c->Generation,c->StopSerial))return OLB_CURRENT;*out=*c;return OLB_OK;}
enum olb_status OlbPinProgramming(OLB_OWNER*o,const OLB_IO*i,uint64_t id){OLB_CLAIM c;enum olb_status s=OlbCheck(o,i,id,&c);if(s)return s;find(o,id)->State=OLB_PROGRAM_PINNED;return OLB_OK;}
enum olb_status OlbReleaseUnpublished(OLB_OWNER*o,const OLB_IO*i,uint64_t id){OLB_CLAIM*c=find(o,id);if(!c||args(i)||c->State==OLB_PROGRAM_PINNED||c->State==OLB_RETAINED)return OLB_TOKEN;
 enum olb_status s=fresh(o,i,c);if(s){c->State=OLB_RETAINED;return s;}o->BankMask&=~(1u<<c->Bank);o->SlotMask&=~(1u<<c->Slot);memset(c,0,sizeof(*c));return OLB_OK;
}

enum olb_status OlbCheckPinned(OLB_OWNER*o,const OLB_IO*i,uint64_t id,OLB_CLAIM*out){OLB_CLAIM*c=find(o,id);if(!c||!out||args(i)||c->State!=OLB_PROGRAM_PINNED)return OLB_TOKEN;if(c->Generation!=o->Generation||i->current(i->Context,c->Generation,c->StopSerial))return OLB_CURRENT;*out=*c;return OLB_OK;}
