#include "qtb_once.h"
#include <string.h>
#if OPEN_QTB_WITNESS
static int authority(const struct qtb_io *o){return o->current(o->ctx);}
static int clean(const struct qtb_io *o){return o->cleanup(o->ctx);}
static int qtb_poll(const struct qtb_io *o,struct qtb_report *r,int halt){
 uint64_t start=o->now_us(o->ctx),now;
 /* Time bound is local, not a promise that a synchronous MMIO bus fault returns.
  * Iteration bound additionally terminates a broken/nonadvancing clock. */
 for(unsigned n=0;n<10000;n++){
  if(authority(o))return -1;
  if(halt){if(o->read64(o->ctx,Q_ACK,&r->ack))return -1;if(r->ack&1)goto done;}
  else {if(o->read64(o->ctx,Q_STATUS,&r->status)||o->read64(o->ctx,Q_OUT,&r->out))return -1;if((r->status|r->out)&1)goto done;}
  now=o->now_us(o->ctx);if(now<start||now-start>=100)goto timeout;
 }
 timeout:now=o->now_us(o->ctx);if(halt)r->halt_us=now-start;else r->ecats_us=now-start;return 1;
 done:now=o->now_us(o->ctx);if(halt)r->halt_us=now-start;else r->ecats_us=now-start;return 0;
}
#endif
enum qtb_result qtb_once(const struct qtb_io *o,struct qtb_report *r){
 if(!r)return QTB_REFUSED;memset(r,0,sizeof(*r));r->result=QTB_DISABLED;
#if !OPEN_QTB_WITNESS
 (void)o;return r->result;
#else
 uint64_t v=0;uint32_t ctl=0;int p,ok=1,acquired=0;
 r->result=QTB_REFUSED;
 if(!o||!o->acquire||!o->current||!o->cleanup||!o->read64||!o->write64||!o->read_sctlr||!o->write_sctlr||!o->faults||!o->sync32||!o->now_us||!o->finish)return r->result;
 if(o->acquire(o->ctx,&r->iova,&r->expected_mdl_pa))return r->result;
 acquired=1;r->attempted=1;r->expected_pfn=r->expected_mdl_pa>>12;
 if(!r->iova||r->iova>>49||(r->iova&4095)||!r->expected_mdl_pa||(r->expected_mdl_pa&4095)||authority(o))goto end;
 if(o->read64(o->ctx,Q_REQ,&r->req_before)||o->read64(o->ctx,Q_TRIGGER,&v)||o->read_sctlr(o->ctx,&r->original_sctlr)||o->faults(o->ctx,&r->fsr,&r->far,&r->syndrome,&r->other_fault)){r->result=QTB_IO;goto end;}
 if((r->req_before&1)||v||r->fsr||r->other_fault)goto end;
 if(authority(o)){r->result=QTB_IO;goto end;}
 r->halt_attempted=1; /* record BEFORE store: failed write may have reached HW */
 if(o->write64(o->ctx,Q_REQ,r->req_before|1)){r->result=QTB_IO;goto restore;}
 p=qtb_poll(o,r,1);if(p){r->result=p<0?QTB_IO:QTB_HALT_TIMEOUT;goto restore;}
 if(authority(o)){r->result=QTB_IO;goto restore;}
 r->sctlr_attempted=1;
 if(o->write_sctlr(o->ctx,r->original_sctlr&~UINT32_C(0xc0))){r->result=QTB_IO;goto restore;}
 if(o->read_sctlr(o->ctx,&ctl)||ctl!=(r->original_sctlr&~UINT32_C(0xc0))){r->result=QTB_IO;goto restore;}
 /* No SID/flags arguments: exactly SID0, coherent NS privileged instruction READ. */
 if(authority(o)||o->write64(o->ctx,Q_IN0,0)||authority(o)||o->write64(o->ctx,Q_IN1,0x3408)||authority(o)||o->write64(o->ctx,Q_IN2,r->iova)||authority(o)){r->result=QTB_IO;goto restore;}
 r->trigger_attempted=1;
 if(o->write64(o->ctx,Q_TRIGGER,1)){r->result=QTB_IO;goto restore;}
 p=qtb_poll(o,r,0);r->result=p<0?QTB_IO:p?QTB_TIMEOUT:QTB_MATCH;
 /* Preserve raw data BEFORE restoring CFIE can invoke existing fault ISR. */
 if(o->faults(o->ctx,&r->fsr,&r->far,&r->syndrome,&r->other_fault))r->result=QTB_IO;
 else if((r->out&1)||r->fsr||r->other_fault)r->result=QTB_FAULT;
 r->extracted=r->out>>12; /* exact vendor FIELD_GET, NOT guessed PAR/PFN scaling */
 if(r->result==QTB_MATCH&&r->extracted!=r->expected_mdl_pa)r->result=QTB_MISMATCH;
 restore:
 r->translation_result=r->result;
 /* Intentionally do NOT call normal current(): a fault may have poisoned it.
  * Check immutable cleanup capability before EACH access. Continue independent
  * restoration attempts after a returned failure; never retry any store. */
 if(r->trigger_attempted){if(clean(o)||o->write64(o->ctx,Q_TRIGGER,0))ok=0;}
 if(r->sctlr_attempted){if(clean(o)||o->write_sctlr(o->ctx,r->original_sctlr))ok=0;}
 if(r->halt_attempted){
  /* Cannot overwrite foreign changed bits. Restore only if all other bits match. */
  if(clean(o)||o->read64(o->ctx,Q_REQ,&v)||(v&~UINT64_C(1))!=r->req_before)ok=0;
  else if(clean(o)||o->write64(o->ctx,Q_REQ,r->req_before))ok=0;
 }
 if(clean(o)||o->sync32(o->ctx))ok=0;
 if(r->trigger_attempted&&(clean(o)||o->read64(o->ctx,Q_TRIGGER,&v)||v))ok=0;
 if(r->sctlr_attempted&&(clean(o)||o->read_sctlr(o->ctx,&ctl)||ctl!=r->original_sctlr))ok=0;
 if(r->halt_attempted&&(clean(o)||o->read64(o->ctx,Q_REQ,&v)||v!=r->req_before))ok=0;
 r->cleanup_restored=ok;r->uncertain=!ok;if(!ok)r->result=QTB_IO;
 end:
 /* Every nonmatch is retained; even clean MATCH is terminal and retains leases. */
 if(acquired)o->finish(o->ctx,r->uncertain||r->result!=QTB_MATCH);
 return r->result;
#endif
}
