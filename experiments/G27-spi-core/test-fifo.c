/* SPDX-License-Identifier: GPL-2.0-only */
#include "geni_fifo.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (UINT32_C(1)<<(n))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define BITS_PER_BYTE 8
#define GENMASK(h,l) ((UINT32_MAX << (l)) & (UINT32_MAX >> (31u-(h))))
#include "original-defines.inc"
#define GENI_SE_FIFO 1
#define GENI_SE_DMA 2
#define CHECKSUM_MODE_U8_LE 0
#define GFP_KERNEL 0
#define ENOMEM 12
#define SPI_LOG_DBG(...) ((void)0)
#define SPI_LOG_ERR(...) ((void)0)
#define dev_err(...) ((void)0)
#define TPD_INFO(...) ((void)0)
#define mb() ((void)0)

struct model {
    uint32_t reg[1024], rx_words[16],rx_index;
    struct {uint32_t offset,value;} writes[20000];
    uint32_t nw,reads,barriers,fail_read,fail_write,fail_barrier;
};
static u32 read_model(struct model*m,u32 off) {
    assert(!(off&3)&&off<sizeof(m->reg));m->reads++;
    if(off==0x780) {assert(m->rx_index<16);return m->rx_words[m->rx_index++];}
    return m->reg[off/4];
}
static void write_model(struct model*m,u32 off,u32 value) {
    assert(!(off&3)&&off<sizeof(m->reg)&&m->nw<20000);
    m->writes[m->nw].offset=off;m->writes[m->nw++].value=value;
    if(off==0x618)m->reg[0x610/4]&=~value;
    else m->reg[off/4]=value;
    if(off==0x600)m->reg[0x40/4]=1;
}
static int io_read(void*p,u32 off,u32*v) {
    struct model*m=p;*v=read_model(m,off);
    return m->fail_read&&m->reads==m->fail_read;
}
static int io_write(void*p,u32 off,u32 v) {
    struct model*m=p;write_model(m,off,v);
    /* Model an applied write whose acknowledgement failed. */
    return m->fail_write&&m->nw==m->fail_write;
}
static int io_barrier(void*p) {
    struct model*m=p;m->barriers++;return m->fail_barrier&&m->barriers==m->fail_barrier;
}
static u32 geni_read_reg(void*p,u32 off){return read_model(p,off);}
static void geni_write_reg(u32 v,void*p,u32 off){write_model(p,off,v);}
/* Extracted packing code uses byte-offset pointer arithmetic, like MMIO. */
static struct model *packing_model;
static void writel_relaxed(u32 v,void*p) {
    uintptr_t off=(uintptr_t)p-(uintptr_t)packing_model;
    assert(off<sizeof(packing_model->reg));write_model(packing_model,(u32)off,v);
}
struct geni_se {void *base;};
struct spi_transfer {
    const void *tx_buf;void *rx_buf;u32 len,bits_per_word,speed_hz,cs_change;
    int transfer_list;uintptr_t tx_dma,rx_dma;
};
struct message {int transfers;};
struct spi_master {int slave;struct message *cur_msg;};
struct spi_geni_master {
    void *base,*dev,*ipc;struct geni_se spi_rsc;
    int tx_fifo_width,tx_fifo_depth,tx_wm,cur_word_len,disable_dma,cur_xfer_mode;
    u32 cur_speed_hz,tx_rem_bytes,rx_rem_bytes;struct spi_transfer *cur_xfer;
};
static bool list_is_last(void*a,void*b){(void)a;(void)b;return true;}
static void spi_setup_word_len(struct spi_geni_master*m,u32 mode,int bpw) {
    (void)m;(void)mode;(void)bpw;assert(!"unqualified word-length service");
}
static int get_spi_clk_cfg(u32 hz,struct spi_geni_master*m,int*idx,int*div) {
    (void)hz;(void)m;(void)idx;(void)div;assert(!"unqualified clock service");return -1;
}
static void geni_se_select_mode(struct geni_se*s,int mode) {
    (void)s;assert(mode==GENI_SE_FIFO); /* Mode already configured in owner. */
}
static void geni_se_setup_m_cmd(struct geni_se*s,u32 cmd,u32 param) {
    write_model(s->base,0x600,(cmd<<27)|(param&0x7ffffff));
}
static int geni_se_rx_dma_prep(struct geni_se*s,void*b,u32 n,uintptr_t*d) {
    (void)s;(void)b;(void)n;(void)d;assert(!"DMA must be unreachable");return -1;
}
static int geni_se_tx_dma_prep(struct geni_se*s,void*b,u32 n,uintptr_t*d) {
    return geni_se_rx_dma_prep(s,b,n,d);
}
struct spi_device {int unused;};
struct chip_data_brl {struct spi_device*s_client;};
struct spi_message {struct spi_transfer*xfer;};
static void *kzalloc(size_t n,int f){(void)f;return calloc(1,n);}
static void kfree(void*p){free(p);}
static void spi_message_init(struct spi_message*m){m->xfer=0;}
static void spi_message_add_tail(struct spi_transfer*x,struct spi_message*m){m->xfer=x;}
static uint8_t captured_tx[4096];static u32 captured_len;
static int spi_sync(struct spi_device*d,struct spi_message*m) {
    (void)d;assert(m->xfer->len<=sizeof(captured_tx));
    captured_len=m->xfer->len;memcpy(captured_tx,m->xfer->tx_buf,captured_len);
    for(u32 i=0;i<captured_len;i++)((u8*)m->xfer->rx_buf)[i]=(u8)(i*17);
    return 0;
}
#include "original-functions.inc"
_Static_assert(sizeof(struct goodix_fw_version)==28,"stock packed version size");
_Static_assert(offsetof(struct goodix_fw_version,patch_pid)==10,"stock patch PID offset");
_Static_assert(offsetof(struct goodix_fw_version,sensor_id)==23,"stock sensor offset");
_Static_assert(offsetof(struct goodix_fw_version,checksum)==26,"stock checksum offset");

static void model_init(struct model*m) {
    memset(m,0,sizeof(*m));
    m->reg[0x68/4]=0x102;m->reg[0xe24/4]=0x20102864;m->reg[0xe28/4]=0x20104800;
    m->reg[0x48/4]=0x11;m->reg[0x268/4]=4;m->reg[0x25c/4]=3;
    m->reg[0x814/4]=14;m->reg[0x614/4]=BIT(0)|BIT(26)|BIT(27)|BIT(30);
    packing_model=m;struct geni_se se={m};
    geni_se_config_packing(&se,8,4,true,true,true);m->nw=0;
}
static void owner_init(struct g27_fifo*s,struct model*m,u32 limit) {
    struct g27_io io={m,io_read,io_write,io_barrier};
    assert(g27_init(s,io,limit)==0);
}
static void ref_init(struct spi_geni_master*r,struct model*m,struct spi_transfer*x) {
    memset(r,0,sizeof(*r));r->base=m;r->spi_rsc.base=m;r->tx_fifo_depth=16;
    r->tx_fifo_width=32;r->tx_wm=1;r->cur_word_len=8;r->cur_speed_hz=1000000;
    r->disable_dma=1;r->cur_xfer=x;r->tx_rem_bytes=x->len;r->rx_rem_bytes=x->len;
}
static u32 collect(struct model*m,u32 offset,u32*out) {
    u32 n=0;for(u32 i=0;i<m->nw;i++)if(m->writes[i].offset==offset)out[n++]=m->writes[i].value;
    return n;
}
static void feed_rx(struct model*m,const u8*b,u32 bytes) {
    assert(bytes<=64);memset(m->rx_words,0,sizeof(m->rx_words));m->rx_index=0;
    for(u32 i=0;i<bytes;i++)m->rx_words[i/4]|=(u32)b[i]<<(8*(i%4));
    m->reg[0x804/4]=(bytes+3)/4|BIT(31)|((bytes%4)<<28);
}
static u32 random_state=0x85509966;
static u32 rnd(void){random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state;}
static u32 cases;
static void differential_transfer(u32 n,int direction) {
    struct model m,ref;struct g27_fifo s;struct spi_geni_master r;
    u8 tx[4096],rx[4096],expected[4096],rrx[4096];u32 a[1024],b[1024];
    for(u32 i=0;i<n;i++){tx[i]=(u8)rnd();expected[i]=(u8)rnd();}
    memset(rx,0xcc,sizeof(rx));memset(rrx,0xdd,sizeof(rrx));
    model_init(&m);model_init(&ref);owner_init(&s,&m,20000);
    struct spi_transfer x={direction&1?tx:0,direction&2?rrx:0,n,8,1000000,0,0,0,0};
    ref_init(&r,&ref,&x);struct message msg={0};struct spi_master spi={0,&msg};
    assert(setup_fifo_xfer(&x,&r,0,&spi)==0);
    assert(g27_start(&s,direction&1?tx:0,direction&2?rx:0,n)==0);
    const u32 setup_offsets[]={0x25c,0x26c,0x270,0x600,0x80c};
    for(size_t k=0;k<5;k++){
        u32 ac=collect(&m,setup_offsets[k],a),bc=collect(&ref,setup_offsets[k],b);
        assert(ac==bc&&memcmp(a,b,ac*4)==0);
    }
    /* BIT1 remains set: catch accidentally using upstream CS_TOGGLE. */
    assert(m.reg[0x25c/4]==2);
    while((direction&1&&s.tx_done<n)||(direction&2&&s.rx_done<n)) {
        u32 irq=0;
        if((direction&2)&&s.rx_done<n){
            u32 chunk=1+rnd()%64;if(chunk>n-s.rx_done)chunk=n-s.rx_done;
            feed_rx(&m,expected+s.rx_done,chunk);feed_rx(&ref,expected+s.rx_done,chunk);
            geni_spi_handle_rx(&r);irq|=BIT(27);
        }
        if((direction&1)&&s.tx_done<n){geni_spi_handle_tx(&r);irq|=BIT(30);}
        m.reg[0x610/4]=irq;assert(g27_step(&s)==G27_WAIT);
        assert(s.tx_done==(direction&1?n-r.tx_rem_bytes:0));
        assert(s.rx_done==(direction&2?n-r.rx_rem_bytes:0));
    }
    if(direction&1){u32 ac=collect(&m,0x700,a),bc=collect(&ref,0x700,b);assert(ac==bc&&memcmp(a,b,ac*4)==0);}
    if(direction&2)assert(memcmp(rx,expected,n)==0&&memcmp(rx,rrx,n)==0);
    m.reg[0x40/4]=0;m.reg[0x610/4]=1;assert(g27_step(&s)==0&&s.state==G27_DONE);
    assert(g27_step(&s)==G27_EBUSY&&g27_start(&s,tx,rx,n)==G27_EBUSY);
    for(u32 i=0;i<m.nw;i++)assert(m.writes[i].offset!=0x620);
    cases++;
}
static void failure_cases(void) {
    struct model m;struct g27_fifo s;u8 tx[64]={0},rx[64];
    const u32 guarded[]={0x40,0x64,0x68,0xe24,0xe28,0x258,0x224,0x230,0x22c,
       0x250,0x24c,0x268,0x254,0x260,0x264,0x284,0x288,0x48,0x800,0x804,0x610,0x80c,0x810,0x814,0x614,0xe1c,0xe18};
    for(size_t i=0;i<sizeof(guarded)/sizeof(guarded[0]);i++){
        model_init(&m);owner_init(&s,&m,10);u32 off=guarded[i];
        m.reg[off/4]^=off==0xe24||off==0xe28?BIT(16):off==0x230?4:1;
        assert(g27_start(&s,tx,rx,16)==G27_ECONFIG&&m.nw==0);cases++;
    }
    for(u32 i=1;i<=28;i++){
        model_init(&m);owner_init(&s,&m,10);m.fail_read=i;
        assert(g27_start(&s,tx,rx,16)==G27_EIO&&s.state==G27_UNCERTAIN);
        u32 writes=m.nw;assert(g27_step(&s)==G27_EBUSY&&g27_cancel(&s)==G27_EBUSY&&m.nw==writes);cases++;
    }
    for(u32 i=1;i<=5;i++){
        model_init(&m);owner_init(&s,&m,10);m.fail_write=i;
        assert(g27_start(&s,tx,rx,16)==G27_EIO&&s.state==G27_UNCERTAIN);
        assert(m.nw==i&&g27_cancel(&s)==G27_EBUSY&&g27_step(&s)==G27_EBUSY);cases++;
    }
    model_init(&m);owner_init(&s,&m,2);
    assert(g27_start(&s,tx,tx,16)==G27_EINVAL&&m.nw==0);
    assert(g27_start(&s,0,0,16)==G27_EINVAL&&g27_start(&s,tx,rx,0)==G27_EINVAL);
    assert(g27_start(&s,tx,rx,4097)==G27_EINVAL&&m.nw==0);cases+=3;
    assert(g27_start(&s,tx,rx,16)==0);
    m.reg[0x610/4]=1;assert(g27_step(&s)==G27_ECOUNT);
    assert(g27_cancel(&s)==0&&g27_cancel(&s)==G27_EBUSY);
    m.reg[0x610/4]=0;assert(g27_step(&s)==1&&g27_step(&s)==1&&g27_step(&s)==G27_ETIME);
    assert(g27_abort(&s)==0&&g27_abort(&s)==G27_EBUSY);
    m.reg[0x40/4]=0;m.reg[0x610/4]=BIT(5);
    assert(g27_step(&s)==G27_ECANCEL&&s.recovered_idle&&g27_cancel(&s)==G27_EBUSY);cases++;
    const u32 bad_status[]={BIT(1),BIT(2),BIT(3),BIT(24),BIT(25),BIT(28),BIT(29),BIT(31),BIT(4)};
    for(size_t i=0;i<sizeof(bad_status)/sizeof(bad_status[0]);i++){
        model_init(&m);owner_init(&s,&m,10);assert(g27_start(&s,tx,rx,16)==0);
        m.reg[0x610/4]=bad_status[i];assert(g27_step(&s)<0&&s.state==G27_FAILED);cases++;
    }
    const u32 bad_rx[]={17,BIT(31)|(1u<<28),BIT(31)|(5u<<28)|1,5};
    for(size_t i=0;i<sizeof(bad_rx)/sizeof(bad_rx[0]);i++){
        model_init(&m);owner_init(&s,&m,10);assert(g27_start(&s,tx,rx,16)==0);
        m.reg[0x610/4]=BIT(27);m.reg[0x804/4]=bad_rx[i];
        assert(g27_step(&s)==G27_ECOUNT&&m.rx_index==0);cases++;
    }
    model_init(&m);owner_init(&s,&m,1);assert(g27_start(&s,tx,rx,16)==0);
    m.reg[0x610/4]=0;assert(g27_step(&s)==1&&g27_step(&s)==G27_ETIME&&s.state==G27_FAILED);cases++;
    for(u32 i=1;i<=6;i++){
        model_init(&m);owner_init(&s,&m,10);assert(g27_start(&s,tx,rx,16)==0);
        feed_rx(&m,tx,16);m.reg[0x610/4]=BIT(27);m.fail_read=m.reads+i;
        assert(g27_step(&s)==G27_EIO&&s.state==G27_UNCERTAIN);
        u32 count=m.nw;assert(g27_cancel(&s)==G27_EBUSY&&g27_step(&s)==G27_EBUSY&&m.nw==count);cases++;
    }
    for(u32 i=1;i<=6;i++){
        model_init(&m);owner_init(&s,&m,10);assert(g27_start(&s,tx,rx,16)==0);
        m.reg[0x610/4]=BIT(30);m.fail_write=m.nw+i;
        assert(g27_step(&s)==G27_EIO&&s.state==G27_UNCERTAIN);cases++;
    }
    model_init(&m);owner_init(&s,&m,10);m.fail_barrier=4;
    assert(g27_start(&s,tx,rx,16)==G27_EIO&&s.state==G27_UNCERTAIN&&m.nw==4);cases++;
    model_init(&m);owner_init(&s,&m,10);assert(g27_start(&s,tx,rx,16)==0);
    m.reg[0x610/4]=BIT(29);assert(g27_step(&s)==G27_ESTATUS);
    assert(g27_cancel(&s)==0&&m.reg[0x610/4]==0);
    m.reg[0x610/4]=BIT(4)|BIT(29);m.reg[0x40/4]=0;
    assert(g27_step(&s)==G27_ECANCEL&&s.recovered_idle);cases++;
}
static void goodix_cases(void) {
    struct spi_device d={0};struct chip_data_brl c={&d};u8 tx[4096],rx[4096],v[28]={0};
    struct g27_goodix_version decoded;
    const u32 addresses[]={0,0x10014,0x12345678,0xfffff000};
    for(size_t j=0;j<4;j++)for(u32 n=1;n<=4088;n=n<32?n+1:n*2){
        assert(goodix_spi_read(&c,addresses[j],rx,n)==0);
        assert(g27_goodix_read_frame(addresses[j],n,tx,sizeof(tx))==0);
        assert(captured_len==n+8&&memcmp(tx,captured_tx,n+8)==0);
        for(u32 i=0;i<n;i++)assert(rx[i]==(u8)((i+8)*17));cases++;
    }
    memcpy(v,"ABCDEF",6);memcpy(v+10,"9966ABCD",8);v[23]=7;
    for(u32 i=0;i<26;i++){u32 sum=0;for(u32 k=0;k<26;k++)sum+=v[k];v[26]=(u8)sum;v[27]=(u8)(sum>>8);
        assert(checksum_cmp(v,28,0)==0&&g27_goodix_decode_version(v,28,&decoded)==0);
        v[i]^=1;assert(checksum_cmp(v,28,0)!=0&&g27_goodix_decode_version(v,28,&decoded)==G27_ESTATUS);v[i]^=1;cases++;
    }
    assert(strcmp(decoded.patch_pid,"9966ABCD")==0&&decoded.sensor_id==7);
    memset(v,0,sizeof(v));assert(checksum_cmp(v,28,0)==0);
    assert(g27_goodix_decode_version(v,28,&decoded)==G27_ESTATUS);cases++;
    memset(v,0xff,sizeof(v));assert(g27_goodix_decode_version(v,28,&decoded)==G27_ESTATUS);cases++;
    assert(g27_goodix_read_frame(0xffffffff,2,tx,sizeof(tx))==G27_EINVAL);cases++;
}
int main(void) {
    for(u32 n=1;n<=128;n++)for(int d=1;d<=3;d++)differential_transfer(n,d);
    for(u32 i=0;i<256;i++)differential_transfer(1+rnd()%4096,1+(int)(rnd()%3));
    failure_cases();goodix_cases();
    printf("{\"cases\":%u,\"differential_transfer_cases\":640,\"native_hardware\":false,\"source_functions\":6}\n",cases);
    return 0;
}
