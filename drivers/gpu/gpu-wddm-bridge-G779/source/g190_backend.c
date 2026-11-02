/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "g190_backend.h"

static void clear_bytes(void *v, size_t n)
{ uint8_t *p = v; while (n--) *p++ = 0; }
static uint32_t le32(const uint8_t *p)
{ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static int extent(uintptr_t p, size_t n)
{ return p && n && n-1 <= UINTPTR_MAX-p; }
static int overlap(uintptr_t a, size_t n, uintptr_t b, size_t m)
{ return a <= b ? b-a < n : a-b < m; }
static g190_status fail(g190_backend *b, g190_status s)
{ if(b->phase!=G190_FAILED)b->failure_stage=b->stage;b->phase=G190_FAILED; b->failure=s; b->resources_must_retain=1; return s; }
static g190_status rd(g190_backend *,uint32_t,uint32_t *);
static int ops_valid(const g190_ops *o)
{
    return o && o->lease && o->prove_stopped && o->read_reg && o->write_reg &&
        o->barrier && o->now_us && o->wait_us && o->cancelled && o->verify_sha256 &&
        o->firmware_write && o->firmware_read && o->configure_board_stopped;
}
static g190_status stamp(g190_backend *b, uint64_t *now)
{
    if (b->ops.now_us(b->ops.cookie,now) || (b->time_seen && *now < b->last_us))
        return fail(b,G190_CLOCK);
    b->last_us=*now; b->time_seen=1; return G190_OK;
}
static g190_status check(g190_backend *b, uint64_t epoch)
{
    uint32_t ao,g2h;
    if (!b || !b->shared || !ops_valid(&b->ops)) return G190_ARGUMENT;
    if (epoch != b->epoch) return G190_STALE_EPOCH;
    if (b->phase == G190_FAILED) return G190_POISONED;
    if (b->ops.cancelled(b->ops.cookie)) return fail(b,G190_CANCELLED);
    if (b->ops.lease(b->ops.cookie,b->generation)) return fail(b,G190_LEASE_LOST);
    g190_status io=rd(b,G190_AO_STATUS,&ao);if(io)return io;b->last_ao=ao;
    io=rd(b,G190_G2H_INFO,&g2h);if(io)return io;b->last_g2h=g2h;
    if ((ao&G190_AO_FATAL) || (g2h&G190_CM3_FAULT)) return fail(b,G190_FW_ERROR);
    if (b->phase==G190_HFI_READY || b->phase==G190_STARTUP_COMPLETE) {
        uint32_t reset,ready;
        if ((io=rd(b,G190_CM3_RESET,&reset)) || (io=rd(b,G190_HFI_STATUS,&ready))) return io;
        b->hfi_status=ready;
        if (reset || !(ready&1)) return fail(b,G190_STATE);
    }
    return G190_OK;
}
static g190_status bar(g190_backend *b,g190_barrier type)
{ return b->ops.barrier(b->ops.cookie,type) ? fail(b,G190_IO) : G190_OK; }
static g190_status wr(g190_backend *b,uint32_t r,uint32_t v)
{
    b->last_register=r;b->last_register_value=v;b->last_register_write=1;b->last_register_valid=0;
    if(b->ops.write_reg(b->ops.cookie,r,v))return fail(b,G190_IO);
    b->last_register_valid=1;return G190_OK;
}
static g190_status rd(g190_backend *b,uint32_t r,uint32_t *v)
{
    b->last_register=r;b->last_register_write=0;b->last_register_valid=0;
    if(b->ops.read_reg(b->ops.cookie,r,v))return fail(b,G190_IO);
    b->last_register_value=*v;b->last_register_valid=1;return G190_OK;
}
static g190_status deadline(g190_backend *b,uint64_t epoch,uint64_t begin,uint64_t us)
{
    uint64_t now; g190_status s=check(b,epoch); if (s) return s;
    s=stamp(b,&now); if (s) return s;
    if (now<begin || now-begin>=us) return fail(b,G190_TIMEOUT);
    return G190_OK;
}
static g190_status pause_once(g190_backend *b)
{ return b->ops.wait_us(b->ops.cookie,b->limits.wait_us) ? fail(b,G190_IO) : G190_OK; }

g190_status g190_initialize(g190_backend *b,const g190_ops *o,const g190_limits *l,
    volatile uint32_t *m,size_t bytes,uint64_t iova)
{
    if (!b || !ops_valid(o) || !l || b->shared || b->epoch ||
        bytes!=G190_HFI_BYTES || !extent((uintptr_t)m,bytes) || ((uintptr_t)m&4095) ||
        !iova || (iova&4095) || iova>UINT32_MAX-(G190_HFI_BYTES-1) ||
        overlap((uintptr_t)b,sizeof(*b),(uintptr_t)m,bytes) ||
        !l->polls_per_operation || l->polls_per_operation>65536 || !l->wait_us || l->wait_us>1000 ||
        !l->load_us || !l->boot_us || !l->command_us || l->startup_us<l->command_us ||
        l->load_us>60000000 || l->boot_us>60000000 || l->command_us>60000000 || l->startup_us>60000000)
        return G190_ARGUMENT;
    g190_ops saved_ops=*o; g190_limits saved_limits=*l;
    clear_bytes(b,sizeof(*b)); b->ops=saved_ops; b->limits=saved_limits; b->shared=m; b->iova=(uint32_t)iova;
    b->resources_must_retain=1; /*adoption is never a stop/release witness*/
    return G190_OK; /* queue untouched until a real stopped witness */
}

g190_status g190_begin_epoch(g190_backend *b,uint64_t expected,uint64_t stop,uint64_t generation)
{
    uint32_t v; uint64_t now;
    if (!b || !b->shared || !ops_valid(&b->ops) || !generation || !stop) return G190_ARGUMENT;
    if (expected!=b->epoch) return G190_STALE_EPOCH;
    if (b->epoch==UINT64_MAX || stop<=b->stop_serial) return G190_STATE;
    /* Failure here does not overwrite an old session or zero shared storage. */
    if (b->ops.prove_stopped(b->ops.cookie,stop,generation)) return G190_STATE;
    b->epoch++; b->generation=generation; b->stop_serial=stop; b->phase=G190_STOPPED;
    b->failure=G190_OK; b->pending_header=0; b->poll_count=0; b->block_count=0;
    b->startup_acked=0; b->startup_attempted=0; b->reset_released=0; b->resources_must_retain=1;
    b->stage=1;b->failure_stage=0;
    /* Stopped initialization owns stale fault bits; do not mistake those for
     * a newly running-firmware fault before clearing them in this phase. */
    if (b->ops.cancelled(b->ops.cookie)) return fail(b,G190_CANCELLED);
    if (b->ops.lease(b->ops.cookie,generation)) return fail(b,G190_LEASE_LOST);
    g190_status s;
    if ((s=rd(b,G190_CM3_RESET,&v))) return s;
    if (v!=1) return fail(b,G190_STATE);
    if ((s=rd(b,G190_HFI_STATUS,&v))) return s;
    if (v&1) return fail(b,G190_STATE);
    /* Distinct interrupt banks, both masked BEFORE queue reset/CM3 release.
     * Full W1C is exclusive stopped initialization, never an ISR action. */
    if ((s=wr(b,G190_G2H_MASK,UINT32_MAX)) || (s=wr(b,G190_AO_MASK,UINT32_MAX)) ||
        (s=bar(b,G190_COMPLETE))) return s;
    if ((s=rd(b,G190_G2H_MASK,&v))) return s;
    if (v!=UINT32_MAX) return fail(b,G190_STATE);
    if ((s=rd(b,G190_AO_MASK,&v))) return s;
    if (v!=UINT32_MAX) return fail(b,G190_STATE);
    if ((s=wr(b,G190_G2H_CLEAR,UINT32_MAX)) || (s=wr(b,G190_AO_CLEAR,UINT32_MAX))) return s;
    for (unsigned i=0;i<G190_HFI_BYTES/4;++i) b->shared[i]=0;
    b->shared[1]=168; b->shared[2]=6; b->shared[3]=12; b->shared[4]=3; b->shared[5]=3;
    for (unsigned q=0;q<3;++q) {
        volatile uint32_t *h=b->shared+6+12*q;
        h[0]=1; h[1]=b->iova+(q+1)*4096; h[2]=0xa00|q; h[3]=G190_QUEUE_WORDS;
        h[6]=1; h[7]=1; h[8]=1;
    }
    if ((s=bar(b,G190_PUBLISH)) || (s=stamp(b,&now))) return s;
    return G190_OK;
}

g190_status g190_load_image(g190_backend *b,uint64_t epoch,const g190_image *image)
{
    uint64_t begin; uint32_t nonzero=0; g190_status s;
    if (!b || !image || !extent((uintptr_t)image->bytes,image->size) ||
        image->size>G190_MAX_IMAGE_BYTES || !image->expected_blocks || image->expected_blocks>32 ||
        overlap((uintptr_t)image->bytes,image->size,(uintptr_t)b,sizeof(*b)) ||
        overlap((uintptr_t)image->bytes,image->size,(uintptr_t)b->shared,G190_HFI_BYTES)) return G190_ARGUMENT;
    g190_image saved_image=*image; image=&saved_image;
    if (epoch!=b->epoch) return G190_STALE_EPOCH;
    if (b->phase==G190_FAILED) return G190_POISONED;
    if (b->phase!=G190_STOPPED) return G190_STATE;
    b->stage=2;
    for (unsigned i=0;i<32;++i) nonzero|=image->sha256[i];
    if (!nonzero) return G190_ARGUMENT;
    if ((s=check(b,epoch)) || (s=stamp(b,&begin))) return s;
    if (b->ops.verify_sha256(b->ops.cookie,image->bytes,image->size,image->sha256)) return fail(b,G190_FIRMWARE);
    if ((s=g190_plan_image(image,b->blocks,32,&b->block_count))) return fail(b,s);
    for (unsigned pass=0;pass<2;++pass) for (size_t i=0;i<b->block_count;++i) {
        const AdrenoFirmwareBlock *p=b->blocks+i;
        uint32_t base=p->region_identifier==1?0:p->region_identifier==2?0x4000:0x10004000;
        for (uint32_t offset=0;offset<p->bytes;offset+=4) {
            uint32_t wanted=le32(image->bytes+p->payload_offset+offset),actual;
            if ((s=deadline(b,epoch,begin,b->limits.load_us))) return s;
            b->firmware_region=p->region_identifier;b->firmware_offset=p->address-base+offset;
            b->firmware_expected=wanted;b->firmware_observed_valid=0;
            if (!pass) {
                if (b->ops.firmware_write(b->ops.cookie,p->region_identifier,p->address-base+offset,wanted)) return fail(b,G190_IO);
            } else {
                if (b->ops.firmware_read(b->ops.cookie,p->region_identifier,p->address-base+offset,&actual)) return fail(b,G190_IO);
                b->firmware_observed=actual;b->firmware_observed_valid=1;
                if (actual!=wanted) return fail(b,G190_FIRMWARE);
            }
        }
        if ((s=bar(b,G190_COMPLETE))) return s;
    }
    if (b->ops.verify_sha256(b->ops.cookie,image->bytes,image->size,image->sha256)) return fail(b,G190_FIRMWARE);
    if ((s=deadline(b,epoch,begin,b->limits.load_us))) return s;
    b->phase=G190_LOADED; return G190_OK;
}

static g190_status poll_register(g190_backend *b,uint64_t epoch,uint64_t begin,
    uint32_t reg,uint32_t mask,uint32_t expected)
{
    for (uint32_t i=0;i<b->limits.polls_per_operation;++i) {
        uint32_t v; g190_status s=deadline(b,epoch,begin,b->limits.boot_us); if (s) return s;
        if ((s=rd(b,reg,&v))) return s;
        if(reg==G190_FW_RESULT)b->firmware_init_result=v;
        if(reg==G190_HFI_STATUS)b->hfi_status=v;
        if ((v&mask)==expected) return bar(b,G190_COMPLETE);
        if ((s=pause_once(b))) return s;
    }
    return fail(b,G190_TIMEOUT);
}

g190_status g190_boot_firmware(g190_backend *b,uint64_t epoch)
{
    uint32_t v,version; uint64_t begin; g190_status s;
    if (!b) return G190_ARGUMENT;
    if (epoch!=b->epoch) return G190_STALE_EPOCH;
    if (b->phase==G190_FAILED) return G190_POISONED;
    if (b->phase!=G190_LOADED) return G190_STATE;
    b->stage=3;
    if ((s=check(b,epoch)) || (s=stamp(b,&begin))) return s;
    if (b->ops.configure_board_stopped(b->ops.cookie)) return fail(b,G190_IO);
    if ((s=rd(b,G190_CM3_RESET,&v))) return s;
    if (v!=1) return fail(b,G190_STATE);
    if ((s=rd(b,G190_HFI_STATUS,&v))) return s;
    if (v&1) return fail(b,G190_STATE);
    if ((s=rd(b,G190_G2H_MASK,&v))) return s;
    if (v!=UINT32_MAX) return fail(b,G190_STATE);
    if ((s=rd(b,G190_AO_MASK,&v))) return s;
    if (v!=UINT32_MAX) return fail(b,G190_STATE);
    if ((s=rd(b,G190_DTCM_VERSION,&version))) return s;
    b->firmware_version=version;
    if ((s=wr(b,G190_FW_RESULT,0)) || (s=wr(b,G190_BOOT_CONFIG,2)) ||
        (s=wr(b,G190_HFI_QTBL_ADDR,b->iova)) || (s=wr(b,G190_HFI_QTBL_INFO,1)) ||
        (s=bar(b,G190_COMPLETE)) || (s=deadline(b,epoch,begin,b->limits.boot_us))) return s;
    const uint32_t registers[]={G190_FW_RESULT,G190_BOOT_CONFIG,G190_HFI_QTBL_ADDR,G190_HFI_QTBL_INFO};
    const uint32_t values[]={0,2,b->iova,1};
    for(unsigned i=0;i<4;++i) {
        if ((s=rd(b,registers[i],&v))) return s;
        if (v!=values[i]) return fail(b,G190_STATE);
    }
    if ((s=deadline(b,epoch,begin,b->limits.boot_us))) return s;
    b->reset_released=1; /* a failed write is indeterminate, never safe to free */
    b->stage=4;
    if ((s=wr(b,G190_CM3_RESET,0)) || (s=bar(b,G190_COMPLETE))) return s;
    uint32_t mask=version<=0x20010004?UINT32_MAX:0x1ff;
    uint32_t expected=version<=0x20010004?0xbabeface:0x100;
    if ((s=poll_register(b,epoch,begin,G190_FW_RESULT,mask,expected))) return s;
    b->stage=5;b->phase=G190_FW_READY;return G190_OK;
}
g190_status g190_start_hfi(g190_backend *b,uint64_t epoch)
{
    uint64_t begin;g190_status s;
    if(!b||epoch!=b->epoch)return G190_STALE_EPOCH;
    if(b->phase!=G190_BOARD_READY)return G190_STATE;
    if((s=check(b,epoch))||(s=stamp(b,&begin)))return s;
    if ((s=wr(b,G190_HFI_INIT,1)) || (s=bar(b,G190_COMPLETE)) ||
        (s=poll_register(b,epoch,begin,G190_HFI_STATUS,1,1))) return s;
    b->stage=6;b->phase=G190_HFI_READY; return G190_OK;
}

static g190_status queue(g190_backend *b,unsigned q,volatile uint32_t **h,
    volatile uint32_t **data,uint32_t *read,uint32_t *write)
{
    g190_status s=bar(b,G190_ACQUIRE); if (s) return s;
    volatile uint32_t *m=b->shared,*v=m+6+12*q;
    if (m[0] || m[1]!=168 || m[2]!=6 || m[3]!=12 || m[4]!=3 || m[5]!=3 ||
        v[0]!=1 || v[1]!=b->iova+(q+1)*4096 || v[2]!=(0xa00|q) || v[3]!=1024 || v[4]) return fail(b,G190_CORRUPT);
    *read=v[10]; *write=v[11];
    if ((s=bar(b,G190_ACQUIRE))) return s;
    if (*read>=1024 || *write>=1024 || (*read&3) || (*write&3)) return fail(b,G190_CORRUPT);
    *h=v; *data=m+(q+1)*1024; return G190_OK;
}

g190_status g190_submit(g190_backend *b,uint64_t epoch,uint32_t id,const uint32_t *payload,size_t words)
{
    volatile uint32_t *h,*data; uint32_t read,write; uint64_t now; g190_status s;
    if (!b || id>255 || words>254 || (words && !extent((uintptr_t)payload,words*4))) return G190_ARGUMENT;
    if (words && (overlap((uintptr_t)payload,words*4,(uintptr_t)b->shared,G190_HFI_BYTES) ||
        overlap((uintptr_t)payload,words*4,(uintptr_t)b,sizeof(*b)))) return G190_ARGUMENT;
    if (epoch!=b->epoch) return G190_STALE_EPOCH;
    if (b->phase==G190_FAILED) return G190_POISONED;
    if (b->phase!=G190_HFI_READY && b->phase!=G190_STARTUP_COMPLETE) return G190_STATE;
    if (b->pending_header) return G190_BUSY;
    if (b->sequence>=4094) return fail(b,G190_SEQUENCE_EXHAUSTED); /* no ambiguous wrap/reuse */
    if ((s=check(b,epoch)) || (s=stamp(b,&now)) || (s=queue(b,0,&h,&data,&read,&write))) return s;
    uint32_t count=(uint32_t)words+1,padded=(count+3)&~3u;
    if (((read-write-1)&1023)<padded) return G190_NO_SPACE;
    b->sequence++; b->pending_header=(b->sequence<<20)|(count<<8)|id;
    b->command_begin_us=now; b->poll_count=0;
    data[write]=b->pending_header;
    for (size_t i=0;i<words;++i) data[(write+1+(uint32_t)i)&1023]=payload[i];
    for (uint32_t i=count;i<padded;++i) data[(write+i)&1023]=0xfafafafa;
    if ((s=bar(b,G190_PUBLISH))) return s;
    h[11]=(write+padded)&1023;
    if ((s=bar(b,G190_PUBLISH)) || (s=wr(b,G190_H2G_SET,1)) || (s=bar(b,G190_COMPLETE))) return s;
    return G190_OK;
}

g190_status g190_poll(g190_backend *b,uint64_t epoch,g190_reply *out)
{
    volatile uint32_t *h,*data; uint32_t read,write,packet[19]; g190_status s;
    if (!b || !out || overlap((uintptr_t)out,sizeof(*out),(uintptr_t)b,sizeof(*b)) ||
        overlap((uintptr_t)out,sizeof(*out),(uintptr_t)b->shared,G190_HFI_BYTES)) return G190_ARGUMENT;
    if (epoch!=b->epoch) return G190_STALE_EPOCH; /* no caller output/queue changes */
    clear_bytes(out,sizeof(*out));
    if (b->phase==G190_FAILED) return G190_POISONED;
    if (b->phase!=G190_HFI_READY && b->phase!=G190_STARTUP_COMPLETE) return G190_STATE;
    if (!b->pending_header) return G190_STATE;
    if (b->poll_count++>=b->limits.polls_per_operation) return fail(b,G190_TIMEOUT);
    if ((s=deadline(b,epoch,b->command_begin_us,b->limits.command_us)) ||
        (s=queue(b,1,&h,&data,&read,&write))) return s;
    if (read==write) { h[8]=1; s=bar(b,G190_PUBLISH); return s?s:G190_PENDING; }
    uint32_t header=data[read],count=(header>>8)&255,padded=(count+3)&~3u;
    if (count<3 || count>19 || padded>((write-read)&1023)) return fail(b,G190_CORRUPT);
    for (uint32_t i=0;i<count;++i) packet[i]=data[(read+i)&1023];
    if ((s=bar(b,G190_ACQUIRE))) return s;
    uint32_t id=header&255,type=(header>>16)&15;
    if (id==100) { b->asynchronous_error=packet[2]; return fail(b,G190_FW_ERROR); }
    if (type!=1) return fail(b,G190_CORRUPT);
    if ((packet[1]>>20)!=(b->pending_header>>20)) {
        if (b->skipped_acks==UINT32_MAX) return fail(b,G190_CORRUPT);
        ++b->skipped_acks;
        if ((s=bar(b,G190_COMPLETE))) return s;
        h[10]=(read+padded)&1023;
        if ((s=bar(b,G190_PUBLISH))) return s;
        return G190_PENDING;
    }
    if ((id!=126 && id!=(b->pending_header&255)) || packet[1]!=b->pending_header) return fail(b,G190_CORRUPT);
    out->firmware_error=packet[2]; out->wire_header=b->pending_header;
    if (packet[2]) return fail(b,G190_FW_ERROR);
    /* Check cancellation/lease/time again before committing caller-visible success. */
    if ((s=deadline(b,epoch,b->command_begin_us,b->limits.command_us))) return s;
    if ((s=bar(b,G190_COMPLETE))) return s;
    h[10]=(read+padded)&1023;
    if ((s=bar(b,G190_PUBLISH))) return s;
    for (uint32_t i=3;i<count;++i) out->words[i-3]=packet[i];
    out->word_count=count-3; b->pending_header=0; return G190_OK;
}

g190_status g190_startup(g190_backend *b,uint64_t epoch,const AdrenoHfiStartupConfig *c)
{
    static const AdrenoHfiStartupStage stages[]={AdrenoHfiStagePerformance,AdrenoHfiStageBandwidth,AdrenoHfiStageCoreStart,AdrenoHfiStageStart};
    uint32_t payload[159],id; size_t n; uint64_t begin; g190_status s; g190_reply reply;
    if (!b || !c || !extent((uintptr_t)c,sizeof(*c)) ||
        overlap((uintptr_t)c,sizeof(*c),(uintptr_t)b,sizeof(*b)) ||
        overlap((uintptr_t)c,sizeof(*c),(uintptr_t)b->shared,G190_HFI_BYTES) ||
        AdrenoHfiStartupValidate(c)!=AdrenoHfiStartupSuccess) return G190_ARGUMENT;
    if (c->enable_ifpc || c->acd_enable_mask) return G190_UNSUPPORTED;
    if (epoch!=b->epoch) return G190_STALE_EPOCH;
    if (b->phase==G190_FAILED) return G190_POISONED;
    if (b->phase!=G190_HFI_READY || b->pending_header || b->startup_attempted) return G190_STATE;
    if ((s=check(b,epoch)) || (s=stamp(b,&begin))) return s;
    b->startup_attempted=1;
    for (unsigned stage=0;stage<4;++stage) {
        b->stage=7+stage;
        if (AdrenoHfiStartupEncode(c,stages[stage],&id,payload,159,&n)!=AdrenoHfiStartupSuccess) return fail(b,G190_ARGUMENT);
        if ((s=deadline(b,epoch,begin,b->limits.startup_us)) || (s=g190_submit(b,epoch,id,payload,n))) return fail(b,s);
        do {
            if ((s=deadline(b,epoch,begin,b->limits.startup_us))) return s;
            s=g190_poll(b,epoch,&reply);
            if (s==G190_PENDING) { g190_status waited=pause_once(b); if (waited) return waited; }
        } while (s==G190_PENDING);
        if (s) return s;
        if ((s=deadline(b,epoch,begin,b->limits.startup_us))) return s;
        b->startup_acked|=1u<<stage;
    }
    b->stage=11;b->phase=G190_STARTUP_COMPLETE; return G190_OK;
}

uint32_t g190_fault_ack_bits(uint32_t observed)
{ return observed&G190_CM3_FAULT; }

g190_status g190_plan_image(const g190_image *image,AdrenoFirmwareBlock *out,size_t capacity,size_t *count)
{
    static const AdrenoFirmwareRegion regions[]={{0,0x4000,1},{0x4000,0xffc000,2},{0x10004000,0x4000,3}};
    AdrenoFirmwareBlock temporary[32];size_t n=0;uint32_t nonzero=0,regions_seen=0;
    if (!count) return G190_ARGUMENT;
    *count=0;
    if (!image || !out || !extent((uintptr_t)image->bytes,image->size) ||
        image->size>G190_MAX_IMAGE_BYTES || !image->expected_blocks || image->expected_blocks>32 ||
        capacity>32 || !extent((uintptr_t)out,capacity*sizeof(*out)) ||
        overlap((uintptr_t)out,capacity*sizeof(*out),(uintptr_t)image->bytes,image->size)) return G190_ARGUMENT;
    for(unsigned i=0;i<32;++i)nonzero|=image->sha256[i];
    if (!nonzero) return G190_ARGUMENT;
    if (AdrenoFirmwarePlanGmu(image->bytes,image->size,regions,3,temporary,32,&n)!=AdrenoFirmwareSuccess ||
        n!=image->expected_blocks) return G190_FIRMWARE;
    for(size_t i=0;i<n;++i)if(temporary[i].bytes)regions_seen|=1u<<(temporary[i].region_identifier-1);
    if(regions_seen!=7) return G190_FIRMWARE; /*this slice requires ITCM/icache/DTCM payloads*/
    for(size_t i=0;i<n;++i)for(size_t j=0;j<i;++j) {
        const AdrenoFirmwareBlock *a=temporary+i,*b=temporary+j;
        if(a->bytes && b->bytes && (uint64_t)a->address<(uint64_t)b->address+b->bytes &&
            (uint64_t)b->address<(uint64_t)a->address+a->bytes) return G190_FIRMWARE;
    }
    if (n>capacity) return G190_NO_SPACE;
    for(size_t i=0;i<n;++i)out[i]=temporary[i];
    *count=n;return G190_OK;
}

g190_status g190_preflight_run(g190_backend *b,uint64_t expected,
    const g190_image *image,const AdrenoHfiStartupConfig *c)
{
    AdrenoFirmwareBlock plan[32];size_t n;g190_status s;
    if (!b || !b->shared || !ops_valid(&b->ops) || !image || !c ||
        !extent((uintptr_t)c,sizeof(*c)) ||
        overlap((uintptr_t)c,sizeof(*c),(uintptr_t)b,sizeof(*b)) ||
        overlap((uintptr_t)c,sizeof(*c),(uintptr_t)b->shared,G190_HFI_BYTES)) return G190_ARGUMENT;
    if (expected!=b->epoch) return G190_STALE_EPOCH;
    g190_image saved_image=*image;image=&saved_image;
    if (AdrenoHfiStartupValidate(c)!=AdrenoHfiStartupSuccess) return G190_ARGUMENT;
    if (c->enable_ifpc || c->acd_enable_mask) return G190_UNSUPPORTED;
    if ((s=g190_plan_image(image,plan,32,&n))) return s;
    if (overlap((uintptr_t)image->bytes,image->size,(uintptr_t)b,sizeof(*b)) ||
        overlap((uintptr_t)image->bytes,image->size,(uintptr_t)b->shared,G190_HFI_BYTES)) return G190_ARGUMENT;
    if (b->ops.verify_sha256(b->ops.cookie,image->bytes,image->size,image->sha256)) return G190_FIRMWARE;
    return G190_OK;
}
