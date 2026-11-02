/* SPDX-License-Identifier: MIT. Constants derive from selected Open sources. */
#include "open_smmu_activate.h"
#include <string.h>
#define NEED (OSMA_CURRENT|OSMA_PHYSICAL_STOP|OSMA_BANK_STREAM|OSMA_SECURE_ACCESS|OSMA_TABLES_VISIBLE|OSMA_FAULT_HANDLER)
#define NS_MASK UINT32_C(0x00c0fc37)
#define NS_VALUE UINT32_C(0x00c00406)
#define NS_RAZ_PROFILE UINT32_C(0x00001830)
#define FSR_FAULT UINT32_C(0xc00001fe)
static enum osma_status fail(OSMA_SESSION*s,enum osma_status e){s->Status=e;if(s->Writes){s->Phase=OSMA_POISONED;s->MustRetain=1;}else{s->MustRetain=0;s->ScopePinned=0;}return e;}
static int check(OSMA_SESSION*s,const OSMA_REQUEST*q,unsigned extra){return s->LastOwnerStatus=q->Proof.check(q->Proof.Context,&q->Proof,NEED|extra,5,q->Bank,q->Asid,q->Slot);}
static int r32(OSMA_SESSION*s,const OSMA_REQUEST*q,size_t o,uint32_t*v){if(check(s,q,0))return -1;s->Reads++;return q->Io.read32(q->Io.cookie,o,v)||*v==UINT32_MAX;}
static int r64(OSMA_SESSION*s,const OSMA_REQUEST*q,size_t o,uint64_t*v){if(check(s,q,0))return -1;s->Reads++;return q->Io.read64(q->Io.cookie,o,v)||*v==UINT64_MAX;}
static int w32(OSMA_SESSION*s,const OSMA_REQUEST*q,size_t o,uint32_t v){if(check(s,q,(o==0||o==0x10||o==0x70)?OSMA_NS_BLOCK:0))return -1;s->Phase=OSMA_MUTATING;s->MustRetain=1;s->Writes++;return q->Io.write32(q->Io.cookie,o,v);}
static int w64(OSMA_SESSION*s,const OSMA_REQUEST*q,size_t o,uint64_t v){if(check(s,q,0))return -1;s->Phase=OSMA_MUTATING;s->MustRetain=1;s->Writes++;return q->Io.write64(q->Io.cookie,o,v);}
static int barrier(OSMA_SESSION*s,const OSMA_REQUEST*q){return check(s,q,0)||q->Io.barrier(q->Io.cookie);}
static enum osma_status snapshot(OSMA_SESSION*s,const OSMA_REQUEST*q,OSH_SNAPSHOT*v){
 memset(v,0,sizeof(*v));if(r32(s,q,0x20,&v->Id0)||r32(s,q,0x24,&v->Id1)||r32(s,q,0x28,&v->Id2))return OSMA_IO;
 if(v->Id0!=0x4c017e18u||v->Id1!=0x40000016u||v->Id2!=0x5511u)return OSMA_HANDOFF;
 if(r32(s,q,0,&v->Nscr0)||r32(s,q,0x10,&v->Nsacr))return OSMA_IO;
 /* G790 exact-ID profile: optional GCFG fault controls and private VMID/PTM
  * hints read zero in the observed implementation. Do not request them or
  * reinterpret a mismatch as success. Full write/readback equality remains. */
 if(v->Nscr0&NS_RAZ_PROFILE)return OSMA_HANDOFF;
 for(unsigned i=0;i<OSH_SMRS;i++)if(r32(s,q,0x800+4*i,&v->Smr[i])||r32(s,q,0xc00+4*i,&v->S2cr[i]))return OSMA_IO;
 return OSMA_OK;
}
static enum osma_status sync(OSMA_SESSION*s,const OSMA_REQUEST*q,size_t cb,unsigned global){
 size_t request=global?0x70:cb+0x7f0,status=global?0x74:cb+0x7f4;
 if(barrier(s,q))return OSMA_OWNER;
 if(!global&&w32(s,q,cb+0x610,q->Asid))return OSMA_IO;
 if(w32(s,q,request,UINT32_MAX)||barrier(s,q))return OSMA_IO;
 for(unsigned n=0;n<q->PollBudget;n++){uint32_t v;s->Polls++;if(r32(s,q,status,&v))return OSMA_IO;if(!(v&1))return barrier(s,q)?OSMA_OWNER:OSMA_OK;if(n+1<q->PollBudget&&(check(s,q,0)||q->WaitOneUs(q->Io.cookie)))return OSMA_OWNER;}
 return OSMA_TIMEOUT; /* Never submit another sync/rollback after this. */
}
static int image(OSMA_SESSION*s,const OSMA_REQUEST*q){
 const ArmSmmu4KConfig*c=q->TableConfig;const ArmSmmu4KResult*t=q->TableResult;
 if(c->input_bits!=39||c->output_bits!=36||!c->leaf_budget||!t->table_pages||!t->leaf_pages||
    t->leaf_pages>c->leaf_budget||t->start_level!=1||t->upper_region||t->mair!=0xff44||
    t->root_physical!=c->table_physical||(t->root_physical&4095)||
    t->root_physical>=(UINT64_C(1)<<36)||t->table_pages>((UINT64_C(1)<<36)-t->root_physical)/4096)return -1;
 /* Selected source-supported GMU profile: coherent SMMU walk, no TTBR1,
  * 39/36/native4K and explicit noncoherent-client NSH bypass controls;
  * the active producer must qualify this profile, not infer coherence
  * merely from missing DT properties or a cached firmware report.
  * no-stall fault model, HUPCF0, ASID=bank as selected Linux context allocator.
  * Full source MAIR slots are compatible with audited NC0/WB1 leaf indices.
  * G798 explicitly selects defined TBI0/TBI1 controls (bits5/6), not RES1.
  * This GMU image admits only untagged uint32 lower IOVAs from its pinned
  * plan; EPD1 keeps upper walks disabled and TTBR1 has no root. TBI does not
  * change any admitted address. Tagged addresses are not a new accepted ABI.
  * This explicit policy is separate from Linux's PASIZE/SEP construction.
  * G810 does not request the optional S1_ASIDPNE private-ASID hint (bit12).
  * The real allocated ASID remains in both TTBR tags; omitting this hint
  * neither changes the bank claim nor disables translation/fault controls. */
 s->Image=(ArmSmmu4KContextImage){0x1f300,1,0x00803519,0x38071,0xf404ff44,0x0000efe4,0x00c00067,0,
    t->root_physical|((uint64_t)q->Asid<<48),(uint64_t)q->Asid<<48};return 0;
}
static int read_image(OSMA_SESSION*s,const OSMA_REQUEST*q){
 size_t cb=0x20000+q->Bank*0x1000;ArmSmmu4KContextImage*v=&s->Readback;memset(v,0,sizeof(*v));
 return r32(s,q,0x1000+4*q->Bank,&v->cbar)||r32(s,q,0x1800+4*q->Bank,&v->cba2r)||
 r32(s,q,cb+0x30,&v->tcr)||r32(s,q,cb+0x10,&v->tcr2)||r64(s,q,cb+0x20,&v->ttbr0)||
 r64(s,q,cb+0x28,&v->ttbr1)||r32(s,q,cb+0x38,&v->mair0)||r32(s,q,cb+0x3c,&v->mair1)||r32(s,q,cb,&v->sctlr);
}
static int same_image(const ArmSmmu4KContextImage*a,const ArmSmmu4KContextImage*b,unsigned disabled){
 return a->cbar==b->cbar&&a->cba2r==b->cba2r&&a->tcr==b->tcr&&a->tcr2==b->tcr2&&
 a->ttbr0==b->ttbr0&&a->ttbr1==b->ttbr1&&a->mair0==b->mair0&&a->mair1==b->mair1&&
 b->sctlr==(disabled?0:a->sctlr); /* No sheng-specific readback relaxations. */
}
static int args(const OSMA_REQUEST*q){return !q||!q->TableConfig||!q->TableResult||q->Io.register_bytes!=0x40000||
 !q->Io.read32||!q->Io.read64||!q->Io.write32||!q->Io.write64||!q->Io.barrier||!q->WaitOneUs||q->Bank>=OSH_BANKS||
 q->Slot>=OSH_SMRS||q->Asid!=q->Bank||!q->PollBudget||q->PollBudget>1000||
 !q->Proof.Context||!q->Proof.D0||!q->Proof.Bank||!q->Proof.Security||!q->Proof.Tables||!q->Proof.Fault||
 !q->Proof.Generation||!q->Proof.StopSerial||!q->Proof.check;}
static int all_except_slot(const OSH_SNAPSHOT*a,const OSH_SNAPSHOT*b,unsigned slot){
 if(a->Id0!=b->Id0||a->Id1!=b->Id1||a->Id2!=b->Id2||a->Nscr0!=b->Nscr0||a->Nsacr!=b->Nsacr)return 0;
 for(unsigned i=0;i<OSH_SMRS;i++)if(i!=slot&&(a->Smr[i]!=b->Smr[i]||a->S2cr[i]!=b->S2cr[i]))return 0;return 1;
}
static enum osma_status guarded_globals(OSMA_SESSION*s,const OSMA_REQUEST*q,uint32_t smr,uint32_t s2cr){
 OSH_SNAPSHOT now;enum osma_status e=snapshot(s,q,&now);if(e)return e;
 if(!all_except_slot(&s->Expected,&now,q->Slot)||now.Smr[q->Slot]!=smr||now.S2cr[q->Slot]!=s2cr)return OSMA_MISMATCH;
 return OSMA_OK;
}
enum osma_status OsmaActivate(OSMA_SESSION*s,const OSMA_REQUEST*q){
 if(!s||args(q)||s->Phase!=OSMA_NEW||s->Writes)return OSMA_ARGUMENT;
 if(check(s,q,0))return fail(s,OSMA_OWNER);if(image(s,q))return fail(s,OSMA_ARGUMENT);
 OSH_SNAPSHOT again;enum osma_status st=snapshot(s,q,&s->Before);if(st)return fail(s,st);
 st=snapshot(s,q,&again);if(st)return fail(s,st);
 enum osh_status handoff=OshAnalyze(&s->Before,&again,&s->Handoff);
 if(handoff!=OSH_OK&&handoff!=OSH_COLD_FAULT_DEFAULT)return fail(s,OSMA_HANDOFF);
 if(handoff==OSH_OK&&s->Handoff.ProtectedBank==q->Bank)return fail(s,OSMA_HANDOFF);
 /* Cold fault defaults prove no owned/free bank. Before even reading the
  * candidate CB, require the actual dedicated NS-block authority in addition
  * to the mandatory physicalstop/bank/ASID/security/tables/fault producers.
  * SID2 stays unmatched/fault: only the owned exact SID5 slot is published. */
 if(handoff==OSH_COLD_FAULT_DEFAULT&&(!q->Proof.NsBlock||check(s,q,OSMA_NS_BLOCK)))return fail(s,OSMA_GLOBAL_REQUIRED);
 OSH_ROUTE_INFO*g=&s->Handoff.Route[3];unsigned existing=g->Found;
 if(existing&&(g->Mask||g->Index!=q->Slot||(g->Type==0&&(g->Bank!=q->Bank||!g->ReadEligible))))return fail(s,OSMA_HANDOFF);
 if(!existing&&(s->Before.Smr[q->Slot]&0x80000000u))return fail(s,OSMA_HANDOFF);
 /* An unused bank is not automatically ours: actual Bank handle/check above
  * must prove the allocator's exclusive claim. Observations only reject
  * contradictions and protected/foreign routes; they never mint that claim. */
 for(unsigned i=0;i<OSH_SMRS;i++)if(i!=q->Slot&&(s->Before.Smr[i]&0x80000000u)&&
    ((s->Before.S2cr[i]>>16)&3u)==0&&(s->Before.S2cr[i]&255u)==q->Bank)return fail(s,OSMA_HANDOFF);
 if(s->Before.S2cr[q->Slot]&~0x030303ffu)return fail(s,OSMA_HANDOFF);
 size_t cb=0x20000+q->Bank*0x1000;
 if(r32(s,q,cb,&s->BeforeSctlr))return fail(s,OSMA_IO);if(s->BeforeSctlr&1)return fail(s,OSMA_BANK_BUSY);
 s->DesiredNscr0=(s->Before.Nscr0&~NS_MASK)|NS_VALUE;
 unsigned global=(s->DesiredNscr0!=s->Before.Nscr0)||(s->Before.Nsacr&(1u<<26));
 if(global&&(!q->Proof.NsBlock||check(s,q,OSMA_NS_BLOCK)))return fail(s,OSMA_GLOBAL_REQUIRED);
 /* No first store until every ownership/power/security/table/IRQ check and
  * current snapshot/bank contradiction check has passed. */
 s->Phase=OSMA_ADMITTED;s->ScopePinned=1;s->MustRetain=1;s->Expected=s->Before;
 s->Bank=q->Bank;s->Asid=q->Asid;s->Slot=q->Slot;s->BoundProof=q->Proof;s->ActivationStopSerial=q->Proof.StopSerial;s->IoIdentity=q->Io.cookie;
 uint32_t faulted=(s->Before.S2cr[q->Slot]&~0x30000u)|0x20000u,v;
 if(w32(s,q,0xc00+4*q->Slot,faulted)||barrier(s,q)||r32(s,q,0xc00+4*q->Slot,&v)||v!=faulted)return fail(s,OSMA_MISMATCH);
 if(global){
  if(s->Before.Nsacr&(1u<<26)){uint32_t a=s->Before.Nsacr&~(1u<<26);
   if(check(s,q,OSMA_NS_BLOCK)||w32(s,q,0x10,a)||barrier(s,q)||r32(s,q,0x10,&v)||v!=a)return fail(s,OSMA_MISMATCH);s->Expected.Nsacr=a;}
  st=sync(s,q,cb,1);if(st)return fail(s,st);
  if(check(s,q,OSMA_NS_BLOCK)||w32(s,q,0,s->DesiredNscr0)||barrier(s,q)||r32(s,q,0,&s->After.Nscr0)||s->After.Nscr0!=s->DesiredNscr0)return fail(s,OSMA_MISMATCH);
  s->Expected.Nscr0=s->DesiredNscr0;
 }
 st=guarded_globals(s,q,s->Before.Smr[q->Slot],faulted);if(st)return fail(s,st);
 if(w32(s,q,cb,0)||barrier(s,q)||r32(s,q,cb,&v)||v)return fail(s,OSMA_MISMATCH);
 st=guarded_globals(s,q,s->Before.Smr[q->Slot],faulted);if(st)return fail(s,st);
 /* Exact qsmmuv500 init_cb ACTLR policy precedes context programming and its
  * required invalidation. Faulted/quiesced streams cannot walk this bank. */
 if(w32(s,q,cb+4,0x32b)||barrier(s,q)||r32(s,q,cb+4,&v)||v!=0x32b)return fail(s,OSMA_MISMATCH);
 st=sync(s,q,cb,0);if(st)return fail(s,st);
 if(w32(s,q,0x1800+4*q->Bank,s->Image.cba2r)||w32(s,q,0x1000+4*q->Bank,s->Image.cbar)||
    w32(s,q,cb+0x10,s->Image.tcr2)||w32(s,q,cb+0x30,s->Image.tcr)||
    w64(s,q,cb+0x20,s->Image.ttbr0)||w64(s,q,cb+0x28,s->Image.ttbr1)||
    w32(s,q,cb+0x38,s->Image.mair0)||w32(s,q,cb+0x3c,s->Image.mair1)||
    r32(s,q,cb+0x58,&v)||w32(s,q,cb+0x58,v&FSR_FAULT)||barrier(s,q))return fail(s,OSMA_IO);
 st=sync(s,q,cb,0);if(st)return fail(s,st);
 st=guarded_globals(s,q,s->Before.Smr[q->Slot],faulted);if(st)return fail(s,st);
 if(read_image(s,q)||!same_image(&s->Image,&s->Readback,1))return fail(s,OSMA_MISMATCH);
 if(w32(s,q,cb,s->Image.sctlr)||barrier(s,q)||read_image(s,q)||!same_image(&s->Image,&s->Readback,0))return fail(s,OSMA_MISMATCH);
 if(r32(s,q,cb+0x58,&s->Fault))return fail(s,OSMA_IO);if(s->Fault&FSR_FAULT)return fail(s,OSMA_FAULT);
 if(!existing&&(w32(s,q,0x800+4*q->Slot,0x80000005u)||barrier(s,q)))return fail(s,OSMA_IO);
 s->FinalS2cr=0x300u|q->Bank; /* TRANS, DEFAULT privilege, source NSH bypass. */
 if(w32(s,q,0xc00+4*q->Slot,s->FinalS2cr)||barrier(s,q))return fail(s,OSMA_IO);
 st=snapshot(s,q,&s->After);if(st)return fail(s,st);
 if(!all_except_slot(&s->Expected,&s->After,q->Slot)||s->After.Smr[q->Slot]!=0x80000005u||s->After.S2cr[q->Slot]!=s->FinalS2cr)return fail(s,OSMA_MISMATCH);
 s->Phase=OSMA_ACTIVE;return s->Status=OSMA_OK;
}
enum osma_status OsmaDisableStopped(OSMA_SESSION*s,const OSMA_REQUEST*q){
 if(!s||args(q)||s->Phase!=OSMA_ACTIVE)return OSMA_ARGUMENT;
 if(q->Bank!=s->Bank||q->Asid!=s->Asid||q->Slot!=s->Slot||q->Io.cookie!=s->IoIdentity||
    q->Proof.Context!=s->BoundProof.Context||q->Proof.D0!=s->BoundProof.D0||q->Proof.Bank!=s->BoundProof.Bank||
    q->Proof.Security!=s->BoundProof.Security||q->Proof.Tables!=s->BoundProof.Tables||q->Proof.Fault!=s->BoundProof.Fault||
    q->Proof.Pas!=s->BoundProof.Pas||q->Proof.NsBlock!=s->BoundProof.NsBlock||q->Proof.check!=s->BoundProof.check||
    q->Proof.Generation!=s->BoundProof.Generation||q->Proof.StopSerial<=s->ActivationStopSerial)return OSMA_OWNER;
 if(check(s,q,0))return fail(s,OSMA_OWNER);OSH_SNAPSHOT now;enum osma_status st=snapshot(s,q,&now);if(st)return fail(s,st);
 if(memcmp(&now,&s->After,sizeof(now))||read_image(s,q)||!same_image(&s->Image,&s->Readback,0))return fail(s,OSMA_MISMATCH);
 size_t cb=0x20000+q->Bank*0x1000;uint32_t v,faulted=(s->FinalS2cr&~0x30000u)|0x20000u;
 if(w32(s,q,0xc00+4*q->Slot,(s->FinalS2cr&~0x30000u)|0x20000u)||barrier(s,q)||
    r32(s,q,0xc00+4*q->Slot,&v)||v!=((s->FinalS2cr&~0x30000u)|0x20000u))return fail(s,OSMA_MISMATCH);
 st=guarded_globals(s,q,s->After.Smr[q->Slot],faulted);if(st)return fail(s,st);
 if(w32(s,q,cb,0)||barrier(s,q)||r32(s,q,cb,&v)||v)return fail(s,OSMA_MISMATCH);
 st=guarded_globals(s,q,s->After.Smr[q->Slot],faulted);if(st)return fail(s,st);
 st=sync(s,q,cb,0);if(st)return fail(s,st);
 s->Phase=OSMA_DISABLED;s->MustRetain=0;return s->Status=OSMA_OK;
}
/* Same continuously held cold scope, just before its owned GBIF handoff.
 * No stores/ACKs: verify the actual published image, exact routes and faults. */
enum osma_status OsmaWitnessActiveHeld(OSMA_SESSION*s,const OSMA_REQUEST*q){
 if(!s||args(q)||s->Phase!=OSMA_ACTIVE||q->Bank!=s->Bank||q->Asid!=s->Asid||q->Slot!=s->Slot||q->Io.cookie!=s->IoIdentity||q->Proof.Context!=s->BoundProof.Context||q->Proof.StopSerial!=s->ActivationStopSerial)return OSMA_ARGUMENT;
 if(check(s,q,OSMA_NS_BLOCK))return fail(s,OSMA_OWNER);OSH_SNAPSHOT now;enum osma_status st=snapshot(s,q,&now);uint32_t v=0;
 if(st)return fail(s,st);if(memcmp(&now,&s->After,sizeof(now))||read_image(s,q)||!same_image(&s->Image,&s->Readback,0))return fail(s,OSMA_MISMATCH);
 size_t cb=0x20000+q->Bank*0x1000;if(r32(s,q,cb+4,&v)||v!=0x32b||r32(s,q,cb+0x58,&v))return fail(s,OSMA_IO);if(v&FSR_FAULT)return fail(s,OSMA_FAULT);return OSMA_OK;
}
