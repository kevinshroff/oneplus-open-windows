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
 s->last_io=s->io.read(s->io.cookie,b,o,v);if(s->last_io)return CGH_IO_ERROR;s->last_value=*v;return *v==UINT32_MAX?CGH_IO_ERROR:CGH_OK;
}
static enum cgh_status cold(CGH_HOLD*s){
 enum cgh_status e;static const uint32_t tcs[4]={0xd28,0xfc8,0x1268,0x1508};
 if((e=rd(s,CGH_CORE,0x14000,&s->reset))||(e=rd(s,CGH_CORE,0x14600,&s->hfi))||(e=rd(s,CGH_CORE,0x14340,&s->gx))||(e=rd(s,CGH_CORE,0x24c40,&s->fence)))return e;
 /* Strong cold-only profile: CM3 already reset, no HFI and actual GX GDSC
  * off. No assumption that a sleeping clock alone means stopped GX. */
 if(s->reset!=1||(s->hfi&1)||!(s->gx&1)||s->fence)return CGH_NOT_COLD;
 /* G732: RSCC_TCSx_DRV0_STATUS bit0 is a READ-ONLY HW status: 1 = TCS idle/votes
  * completed (set only by GMU fw RPMh activity; nobody software-writes it — kgsl
  * polls it only at power-off, Mesa ignores the result). A genuinely cold,
  * never-voted GPU RSC legitimately reads 0. Record, do not gate. */
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
 {enum cgh_status e1=haltword(s,&a);
  if(e1==CGH_IO_ERROR){ /* G730: GPU/GBIF bank unreadable (GX domain down pre-GMU).
   * kgsl never touches +0xf114/f118 before GMU boot; hold via the readable
   * GMU-window cold state alone; the halt handshake is skipped and marked. */
   s->deferred=1;s->owned=1;s->before_halt=0;s->state=CGH_HELD;s->error=CGH_OK;return CGH_OK;}
  if(e1)return fail(s,e1);}
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
 if(s->deferred){if((e=cold(s)))return fail(s,e);s->io.barrier(s->io.cookie);return CGH_OK;}
 if((e=cold(s))||(e=haltword(s,&v))||(e=ackword(s)))return fail(s,e);
 if(v!=(s->before_halt|OWN)||!(s->last_ack&OWN))return fail(s,CGH_FOREIGN);
 s->io.barrier(s->io.cookie);return CGH_OK;
}
enum cgh_status CghReleaseToReset(CGH_HOLD*s,unsigned budget){
 enum cgh_status e;uint32_t v;if(!s||!budget||budget>10000)return CGH_ARGUMENT;
 if((e=CghCheck(s)))return e;
 if(s->deferred){s->owned=0;s->state=CGH_RELEASED;s->error=CGH_OK;return CGH_OK;}
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
 if(s->deferred){if((e=cold(s)))return fail(s,e);s->io.barrier(s->io.cookie);return CGH_OK;}
 if((e=cold(s))||(e=haltword(s,&v))||(e=ackword(s)))return fail(s,e);
 if(v!=s->before_halt||(s->last_ack&OWN))return fail(s,CGH_FOREIGN);
 s->io.barrier(s->io.cookie);return CGH_OK;
}
