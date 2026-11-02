/* SPDX-License-Identifier: GPL-2.0-only
 * Register/packing/transfer behavior derived from pinned OnePlus kernel
 * c87f74901db572a762241d6dfcacc42dbdd9f798 drivers/spi/spi-msm-geni.c,
 * drivers/soc/qcom/qcom-geni-se.c and include/linux/qcom-geni-se.h.
 * Goodix framing: modules/devicetree 46cfd06fc4c0e12dbe294badb924a533f1d9fb06.
 */
#include "geni_fifo.h"
#define BIT(n) (UINT32_C(1)<<(n))
#define IRQ_DONE BIT(0)
#define IRQ_CANCEL BIT(4)
#define IRQ_ABORT BIT(5)
#define IRQ_RX (BIT(26)|BIT(27))
#define IRQ_TX BIT(30)
#define IRQ_ERROR (BIT(1)|BIT(2)|BIT(3)|BIT(24)|BIT(25)|BIT(28)|BIT(29))
#define FIFO_WORDS 16u
#define MAX_LENGTH 4096u

static int rd(struct g27_fifo *s,uint32_t a,uint32_t *v) {
    if(s->io.read32(s->io.context,a,v)) {
        s->state=G27_UNCERTAIN;s->failure=G27_EIO;return G27_EIO;
    } return G27_OK;
}
static int wr(struct g27_fifo *s,uint32_t a,uint32_t v) {
    if(s->io.write32(s->io.context,a,v) || s->io.barrier(s->io.context)) {
        s->state=G27_UNCERTAIN;s->failure=G27_EIO;return G27_EIO;
    } return G27_OK;
}
static int fail(struct g27_fifo *s,int e) {
    s->state=G27_FAILED;s->failure=e;return e;
}
int g27_init(struct g27_fifo *s,struct g27_io io,uint32_t limit) {
    if(!s||!io.read32||!io.write32||!io.barrier||!limit||limit>100000u)
        return G27_EINVAL;
    s->io=io;s->state=G27_IDLE;s->failure=0;s->tx=0;s->rx=0;
    s->length=0;s->tx_done=0;s->rx_done=0;s->steps=0;s->step_limit=limit;
    s->last_irq=0;s->cancel_sent=0;s->abort_sent=0;s->recovered_idle=0;return G27_OK;
}
int g27_start(struct g27_fifo *s,const uint8_t *tx,uint8_t *rx,uint32_t n) {
    uint32_t v,trans;
    /* Masks preserve reserved bits; literal values checked against source. */
    static const uint32_t checks[][3]={
        {0x40,0x1001,0}, {0x64,1,0}, {0x68,0xffff,0x102},
        {0xe24,0x3f3f0000,0x20100000}, {0xe28,0x3f3f0000,0x20100000},
        {0x258,1,0}, {0x224,1,0}, {0x230,4,0}, {0x22c,3,0},
        {0x250,15,0}, {0x24c,1,0}, {0x268,0x3ff,4}, {0x254,3,0},
        {0x260,0xffffffff,0x7f8fe}, {0x264,0xffffffff,0xffefe},
        {0x284,0xffffffff,0x7f8fe}, {0x288,0xffffffff,0xffefe},
        {0x48,1,1}, {0x800,0x0fffffff,0}, {0x804,0x81ffffff,0},
        {0x610,0xffffffff,0},
        {0x80c,0x3f,0}, {0x810,0x3f,0}, {0x814,0x3f,14},
        {0x614,IRQ_DONE|IRQ_RX|IRQ_TX,IRQ_DONE|IRQ_RX|IRQ_TX},
        /* Caller must mask physical IRQ/GPI delivery for this polled core. */
        {0xe1c,0xffffffff,0}, {0xe18,0xffffffff,0}
    };
    if(!s||s->state!=G27_IDLE) return G27_EBUSY;
    if((!tx&&!rx)||!n||n>MAX_LENGTH) return G27_EINVAL;
    /* In-place/overlapping TX/RX would corrupt unsent bytes. */
    if(tx&&rx) {
        uintptr_t a=(uintptr_t)tx,b=(uintptr_t)rx;
        if(a>UINTPTR_MAX-n||b>UINTPTR_MAX-n|| (a<b+n && b<a+n))
            return G27_EINVAL;
    }
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);i++) {
        if(rd(s,checks[i][0],&v)) return G27_EIO;
        if((v&checks[i][1])!=checks[i][2]) return G27_ECONFIG;
    }
    if(rd(s,0x25c,&trans)) return G27_EIO;
    s->tx=tx;s->rx=rx;s->length=n;s->tx_done=0;s->rx_done=0;s->steps=0;
    /* Source CS_TOGGLE is BIT(0), unlike upstream's BIT(1). */
    if(wr(s,0x25c,trans&~BIT(0))) return G27_EIO;
    if(tx&&wr(s,0x26c,n)) return G27_EIO;
    if(rx&&wr(s,0x270,n)) return G27_EIO;
    s->state=G27_ACTIVE;
    uint32_t cmd=(tx?1u:0u)|(rx?2u:0u);
    if(wr(s,0x600,cmd<<27)) return G27_EIO;
    if(tx&&wr(s,0x80c,1)) return G27_EIO;
    return G27_OK;
}
static int receive(struct g27_fifo *s) {
    uint32_t status,word;
    if(rd(s,0x804,&status)) return G27_EIO;
    uint32_t words=status&0x1ffffff,valid=(status>>28)&7;
    if(words>FIFO_WORDS||valid>4||(!words&&(status&BIT(31))&&valid))
        return fail(s,G27_ECOUNT);
    uint32_t bytes=words*4;
    if((status&BIT(31))&&valid&&valid<4) bytes-=4-valid;
    if(!s->rx||bytes>s->length-s->rx_done) return fail(s,G27_ECOUNT);
    for(uint32_t i=0;i<bytes;) {
        if(rd(s,0x780,&word)) return G27_EIO;
        uint32_t take=bytes-i;if(take>4)take=4;
        for(uint32_t j=0;j<take;j++,i++) s->rx[s->rx_done+i]=(uint8_t)(word>>(8*j));
    }
    s->rx_done+=bytes;return G27_OK;
}
static int transmit(struct g27_fifo *s) {
    if(!s->tx) return fail(s,G27_ECOUNT);
    uint32_t count=s->length-s->tx_done;if(count>60)count=60;
    for(uint32_t i=0;i<count;) {
        uint32_t word=0,take=count-i;if(take>4)take=4;
        for(uint32_t j=0;j<take;j++,i++) word|=(uint32_t)s->tx[s->tx_done+i]<<(8*j);
        if(wr(s,0x700,word)) return G27_EIO;
    }
    s->tx_done+=count;
    if(s->tx_done==s->length&&wr(s,0x80c,0)) return G27_EIO;
    return G27_OK;
}
int g27_step(struct g27_fifo *s) {
    uint32_t irq,status;
    if(!s) return G27_EINVAL;
    if(s->state!=G27_ACTIVE&&s->state!=G27_CANCELLING&&s->state!=G27_ABORTING)
        return G27_EBUSY;
    if(s->steps>=s->step_limit) {
        s->failure=G27_ETIME;
        if(s->state==G27_ACTIVE)s->state=G27_FAILED;
        return G27_ETIME;
    }
    s->steps++;
    if(rd(s,0x610,&irq)) return G27_EIO;
    s->last_irq=irq;
    if(s->state==G27_ACTIVE) {
        /* The pinned vendor ISR handles FIFO/completion bits, then ACKs the
         * whole raw status. Other indications (including observed bit7) do
         * not themselves mean failure. Retain fatal-error checks, strict byte
         * counts, idle proof and the caller's bounded time/command budgets.
         * No name or harmlessness claim is made for undocumented bit21. */
        if(irq&IRQ_ERROR) return fail(s,G27_ESTATUS);
        if(irq&(IRQ_CANCEL|IRQ_ABORT)) return fail(s,G27_ECANCEL);
        if(irq&IRQ_RX) {int e=receive(s);if(e)return e;}
        if(irq&IRQ_TX) {int e=transmit(s);if(e)return e;}
        if(irq&IRQ_DONE) {
            if((s->tx&&s->tx_done!=s->length)||(s->rx&&s->rx_done!=s->length))
                return fail(s,G27_ECOUNT);
            if(rd(s,0x40,&status)) return G27_EIO;
            if(status&0x1001) return fail(s,G27_ESTATUS);
        }
    } else if(irq&(IRQ_DONE|IRQ_CANCEL|IRQ_ABORT)) {
        if(rd(s,0x40,&status)) return G27_EIO;
        if(status&0x1001) return fail(s,G27_ESTATUS);
        if(wr(s,0x618,irq)) return G27_EIO;
        s->recovered_idle=1;
        return fail(s,G27_ECANCEL);
    }
    /* Ack after FIFO handling, matching source order. Never offset0x620. */
    if(irq&&wr(s,0x618,irq)) return G27_EIO;
    if(irq&IRQ_DONE) {s->state=G27_DONE;return G27_OK;}
    return G27_WAIT;
}
int g27_cancel(struct g27_fifo *s) {
    uint32_t stale;
    if(!s||s->cancel_sent||(s->state!=G27_ACTIVE&&s->state!=G27_FAILED)) return G27_EBUSY;
    s->state=G27_CANCELLING;s->steps=0;s->cancel_sent=1;
    if(wr(s,0x80c,0)||rd(s,0x610,&stale)) return G27_EIO;
    /* The error/premature-DONE cause can still be latched. Quiesce and ack
     * this exclusively owned command before sending the one cancel request.
     */
    if(stale&&wr(s,0x618,stale)) return G27_EIO;
    if(wr(s,0x604,BIT(2))) return G27_EIO;
    return G27_OK;
}
int g27_abort(struct g27_fifo *s) {
    if(!s||s->abort_sent||s->state!=G27_CANCELLING) return G27_EBUSY;
    s->state=G27_ABORTING;s->steps=0;s->abort_sent=1;
    return wr(s,0x604,BIT(1));
}
int g27_goodix_read_frame(uint32_t a,uint32_t n,uint8_t *tx,uint32_t cap) {
    if(!tx||!n||n>MAX_LENGTH-G27_GOODIX_READ_PREFIX||cap<n+8||a>UINT32_MAX-(n-1))
        return G27_EINVAL;
    tx[0]=0xf1;tx[1]=(uint8_t)(a>>24);tx[2]=(uint8_t)(a>>16);
    tx[3]=(uint8_t)(a>>8);tx[4]=(uint8_t)a;
    tx[5]=0xff;tx[6]=0xff;tx[7]=0xff;
    for(uint32_t i=8;i<n+8;i++)tx[i]=0;
    return G27_OK;
}
int g27_goodix_decode_version(const uint8_t *b,uint32_t n,struct g27_goodix_version *v) {
    if(!b||!v||n!=G27_GOODIX_VERSION_BYTES) return G27_EINVAL;
    uint32_t sum=0;for(uint32_t i=0;i<n-2;i++)sum+=b[i];
    if((sum&0xffff)!=((uint32_t)b[n-2]|((uint32_t)b[n-1]<<8)))return G27_ESTATUS;
    for(uint32_t i=0;i<4;i++)if(b[10+i]<'0'||b[10+i]>'9')return G27_ESTATUS;
    for(uint32_t i=0;i<6;i++)v->rom_pid[i]=(char)b[i];v->rom_pid[6]=0;
    for(uint32_t i=0;i<8;i++)v->patch_pid[i]=(char)b[10+i];v->patch_pid[8]=0;
    for(uint32_t i=0;i<3;i++)v->rom_vid[i]=b[6+i];
    for(uint32_t i=0;i<4;i++)v->patch_vid[i]=b[18+i];
    v->sensor_id=b[23];return G27_OK;
}
