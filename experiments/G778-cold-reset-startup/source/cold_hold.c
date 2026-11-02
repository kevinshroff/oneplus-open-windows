/* SPDX-License-Identifier: MIT */
#include "cold_hold.h"
#include <string.h>
#define HALT 0xf114u
#define ACK 0xf118u
#define OWN 2u
static enum cgh_status fail(CGH_HOLD*s,enum cgh_status e){s->error=e;s->state=s->attempted?CGH_POISONED:CGH_REFUSED;if(!s->attempted)s->owned=0;return e;}
static int current(CGH_HOLD*s){return s->io.current(s->io.cookie,s->generation)==0;}
static enum cgh_status rd(CGH_HOLD*s,unsigned b,uint32_t o,uint32_t*v){
 if(!current(s))return CGH_OWNER;s->last_bank=b;s->last_offset=o;s->reads++;
 s->last_io=s->io.read(s->io.cookie,b,o,v);if(s->last_io)return CGH_IO_ERROR;s->last_value=*v;if(*v==UINT32_MAX)return CGH_IO_ERROR;
 if(b==CGH_CORE){if(o==0x14000)s->sampled_mask|=1u;else if(o==0x14600)s->sampled_mask|=2u;else if(o==0x14340)s->sampled_mask|=4u;else if(o==0x24c40)s->sampled_mask|=8u;}
 else if(b==CGH_RSC){if(o==0xd28)s->sampled_mask|=16u;else if(o==0xfc8)s->sampled_mask|=32u;else if(o==0x1268)s->sampled_mask|=64u;else if(o==0x1508)s->sampled_mask|=128u;}
 else if(b==CGH_GPU){if(o==HALT)s->sampled_mask|=256u;else if(o==ACK)s->sampled_mask|=512u;}
 return CGH_OK;
}
static enum cgh_status cold(CGH_HOLD*s){
 enum cgh_status e;static const uint32_t tcs[4]={0xd28,0xfc8,0x1268,0x1508};
 if((e=rd(s,CGH_CORE,0x14000,&s->reset))||(e=rd(s,CGH_CORE,0x14600,&s->hfi))||(e=rd(s,CGH_CORE,0x14340,&s->gx))||(e=rd(s,CGH_CORE,0x24c40,&s->fence)))return e;
 /* Strong cold-only profile: CM3 already reset, no HFI and actual GX GDSC
  * off. No assumption that a sleeping clock alone means stopped GX. */
 s->cold_fail_mask=(s->reset!=1?1u:0u)|((s->hfi&1)?2u:0u)|(!(s->gx&1)?4u:0u)|(s->fence?8u:0u);
 if(s->cold_fail_mask)return CGH_NOT_COLD;
 /* G736: TCS status is advisory, not an early-boot programming-enable bit.
  * Vendor polls completion in shutdown; no vendor first-boot requirement.
  * This does not replace physical stop/GBIF or namespace proof. sampled_mask
  * distinguishes measured zero from a field not yet read after early refusal. */
 for(unsigned i=0;i<4;i++){if((e=rd(s,CGH_RSC,tcs[i],&s->tcs[i])))return e;}
 return CGH_OK;
}
static enum cgh_status haltword(CGH_HOLD*s,uint32_t*v){enum cgh_status e=rd(s,CGH_GPU,HALT,v);if(!e)s->last_halt=*v;return e;}
static enum cgh_status ackword(CGH_HOLD*s){return rd(s,CGH_GPU,ACK,&s->last_ack);}
static enum cgh_status store(CGH_HOLD*s,uint32_t before,uint32_t desired){
 if(!current(s))return CGH_OWNER;if(((before^desired)&~OWN)||((before^desired)&OWN)==0)return CGH_FOREIGN;
 s->attempted=1;s->writes++;s->state=CGH_MUTATING;s->last_io=s->io.write_halt(s->io.cookie,before,desired);if(s->last_io)return CGH_IO_ERROR;s->io.barrier(s->io.cookie);return CGH_OK;
}
enum cgh_status CghAcquire(CGH_HOLD*s,const CGH_IO*io,uint64_t serial,unsigned budget){
 enum cgh_status e;uint32_t a,b;
 if(!s||!io||s->state!=CGH_NEW||!serial||!io->generation||!io->current||!io->read||!io->write_halt||!io->barrier||!io->wait10us||!budget||budget>10000)return CGH_ARGUMENT;
 memset(s,0,sizeof(*s));s->io=*io;s->generation=io->generation;s->serial=serial;
 if((e=cold(s)))return fail(s,e);
 /* G736: an unreadable GBIF register does not establish a traffic hold.
  * Refuse before mutation; a future cold-start activation mode must carry
  * its own proof instead of fabricating CGH_HELD/owned. */
 if((e=haltword(s,&a)))return fail(s,e);
 if((e=haltword(s,&b)))return fail(s,e);
 if(a!=b||(b&OWN))return fail(s,CGH_FOREIGN);s->before_halt=b;
 if((e=ackword(s)))return fail(s,e);if(s->last_ack&OWN)return fail(s,CGH_FOREIGN);
 /* Journal before even attempting the only permitted RMW. */
 s->owned=1;if((e=store(s,b,b|OWN)))return fail(s,e);
 for(unsigned i=0;i<budget;i++){
  if((e=cold(s))||(e=haltword(s,&a))||(e=ackword(s)))return fail(s,e);
  s->polls++;if(a!=(s->before_halt|OWN))return fail(s,CGH_FOREIGN);
  if(s->last_ack&OWN){s->state=CGH_HELD;s->error=CGH_OK;return CGH_OK;}
  s->io.wait10us(s->io.cookie);
 }
 return fail(s,CGH_TIMEOUT);
}
enum cgh_status CghCheck(CGH_HOLD*s){
 enum cgh_status e;uint32_t v;if(!s||s->state!=CGH_HELD||!s->owned)return CGH_OWNER;
 if(s->deferred)return fail(s,CGH_OWNER);
 if((e=cold(s))||(e=haltword(s,&v))||(e=ackword(s)))return fail(s,e);
 if(v!=(s->before_halt|OWN)||!(s->last_ack&OWN))return fail(s,CGH_FOREIGN);
 s->io.barrier(s->io.cookie);return CGH_OK;
}
enum cgh_status CghReleaseToReset(CGH_HOLD*s,unsigned budget){
 enum cgh_status e;uint32_t v;if(!s||!budget||budget>10000)return CGH_ARGUMENT;
 if((e=CghCheck(s)))return e;
 if(s->deferred)return fail(s,CGH_OWNER);
 if((e=store(s,s->before_halt|OWN,s->before_halt)))return fail(s,e);
 for(unsigned i=0;i<budget;i++){
  if((e=cold(s))||(e=haltword(s,&v))||(e=ackword(s)))return fail(s,e);s->polls++;
  if(v!=s->before_halt)return fail(s,CGH_FOREIGN);
  if(!(s->last_ack&OWN)){s->owned=0;s->state=CGH_RELEASED;s->error=CGH_OK;return CGH_OK;}
  s->io.wait10us(s->io.cookie);
 }
 return fail(s,CGH_TIMEOUT);
}

enum cgh_status CghCheckReleased(CGH_HOLD*s){
 enum cgh_status e;uint32_t v;if(!s||s->state!=CGH_RELEASED||s->owned)return CGH_OWNER;
 if(s->deferred)return fail(s,CGH_OWNER);
 if((e=cold(s))||(e=haltword(s,&v))||(e=ackword(s)))return fail(s,e);
 if(v!=s->before_halt||(s->last_ack&OWN))return fail(s,CGH_FOREIGN);
 s->io.barrier(s->io.cookie);return CGH_OK;
}

/* This mode relies on actual reset + powered-off master domains, not on
 * ownership of inherited GBIF request/status bits. ACK3 is sampled as the
 * narrow cold profile's idle status; it is never cleared or called owned. */
static enum cgh_status reset_profile(CGH_HOLD*s,uint32_t expected_halt){
 enum cgh_status e;uint32_t a,b;
 if((e=cold(s)))return e;
 if(s->reset!=1||s->hfi!=0||s->gx!=3||s->fence)return CGH_NOT_COLD;
 if((e=haltword(s,&a))||(e=ackword(s))||(e=haltword(s,&b)))return e;
 if(a!=expected_halt||b!=expected_halt)return CGH_FOREIGN;
 if(expected_halt==8&&s->last_ack!=3)return CGH_NOT_COLD;
 return CGH_OK;
}
enum cgh_status CghResetAcquire(CGH_HOLD*s,const CGH_IO*io,uint64_t serial){
 enum cgh_status e;
 if(!s||!io||s->state!=CGH_NEW||!serial||!io->generation||!io->current||!io->read||!io->write_halt||!io->barrier||!io->wait10us)return CGH_ARGUMENT;
 memset(s,0,sizeof(*s));s->io=*io;s->generation=io->generation;s->serial=serial;
 if((e=reset_profile(s,8)))return fail(s,e);
 s->before_halt=8;
 /* Repeat current hardware profile across the acquisition boundary. */
 if((e=reset_profile(s,8)))return fail(s,e);
 s->reset_mode=1;s->owned=0;s->state=CGH_RESET_QUIESCENT;s->error=CGH_OK;
 s->io.barrier(s->io.cookie);return CGH_OK;
}
enum cgh_status CghResetCheck(CGH_HOLD*s){
 enum cgh_status e;
 if(!s||!s->reset_mode||s->state!=CGH_RESET_QUIESCENT||s->owned||s->attempted||s->before_halt!=8||s->deferred)return CGH_OWNER;
 if((e=reset_profile(s,8)))return fail(s,e);
 s->io.barrier(s->io.cookie);return CGH_OK;
}
enum cgh_status CghResetReleaseUnpublished(CGH_HOLD*s){
 enum cgh_status e=CghResetCheck(s);if(e)return e;
 s->state=CGH_RESET_RELEASED;return CGH_OK;
}
enum cgh_status CghResetCheckReleased(CGH_HOLD*s){
 enum cgh_status e;
 if(!s||!s->reset_mode||s->state!=CGH_RESET_RELEASED||s->owned||s->attempted||s->deferred)return CGH_OWNER;
 if((e=reset_profile(s,8)))return fail(s,e);return CGH_OK;
}
enum cgh_status CghResetUnhaltForBoot(CGH_HOLD*s){
 enum cgh_status e=CghResetCheck(s);if(e)return e;
 /* Whole-device request reset is legal only in this distinct cold authority
  * at the actual vendor ordering point. It is not removal of an owned bit.
  * Journal before attempting; uncertainty never recovers stopped authority. */
 s->attempted=1;s->state=CGH_BOOT_UNHALTING;s->writes++;
 if(!current(s))return fail(s,CGH_OWNER);
 s->last_io=s->io.write_halt(s->io.cookie,8,0);
 if(s->last_io)return fail(s,CGH_IO_ERROR);
 s->io.barrier(s->io.cookie);
 if((e=reset_profile(s,0)))return fail(s,e);
 s->state=CGH_BOOT_RELEASED;s->error=CGH_OK;return CGH_OK;
}
enum cgh_status CghResetCheckBootReleased(CGH_HOLD*s){
 enum cgh_status e;
 if(!s||!s->reset_mode||s->state!=CGH_BOOT_RELEASED||s->owned||!s->attempted||s->writes!=1||s->deferred)return CGH_OWNER;
 /* Vendor does not require ACKclear after HALT0; the masters are still reset
  * here. Once firmware runs, the separate native runtime checker is used. */
 if((e=reset_profile(s,0)))return fail(s,e);return CGH_OK;
}
