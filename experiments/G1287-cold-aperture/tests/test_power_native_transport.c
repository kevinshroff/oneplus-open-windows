/* Host-only actual g190 transport with explicit firmware/device model.
 * This tests protocol/failure behavior, not native GMU or power evidence. */
#include "g440_gpu_power.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {
 g190_backend b;g440_gpu_power p;_Alignas(4096) uint32_t mem[4096];
 uint64_t time,request_delay,ack_read_delay;uint32_t info,error;unsigned notifications,requests,clears,ack_clears;
 int no_hfi_ack,no_oob_ack,gx_off,cancel,lease_lost,drop_write,backwards;
} model;
static model m;
static int lease(void*v,uint64_t g){model*x=v;return x->lease_lost||g!=11;}
static int stop(void*v,uint64_t s,uint64_t g){(void)v;return s==0||g!=11;}
static int rd(void*v,uint32_t r,uint32_t*out){model*x=v;switch(r){
 case G190_CM3_RESET:*out=0;break;case G190_HFI_STATUS:*out=1;break;
 case G190_AO_STATUS:*out=0;break;case G190_G2H_INFO:if(x->requests)x->time+=x->ack_read_delay;*out=x->info;break;
 case 0x14340:*out=x->requests&&!x->gx_off?0:3;break;default:assert(0);return -1;}return 0;}
static int wr(void*v,uint32_t r,uint32_t value){model*x=v;if(x->drop_write)return -1;
 if(r==G190_G2H_CLEAR){assert(value==0x80000000u);x->info&=~value;x->ack_clears++;return 0;}
 assert(r==G190_H2G_SET);
 if(value==0x40000000u){x->time+=x->request_delay;x->requests++;if(!x->no_oob_ack)x->info|=0x80000000u;return 0;}
 if(value==0x80000000u){x->clears++;return 0;}
 assert(value==1);x->notifications++;uint32_t*h=x->mem+6,*d=x->mem+1024,ridx=h[10],header=d[ridx];
 assert((header&255)==30&&((header>>8)&255)==4&&d[ridx+1]==1&&d[ridx+2]==1&&d[ridx+3]==1);
 if(!x->no_hfi_ack){h[10]=h[11];h=x->mem+18;d=x->mem+2048;uint32_t w=h[11];d[w]=(1u<<16)|(3u<<8)|30;d[w+1]=header;d[w+2]=x->error;d[w+3]=0xfafafafa;h[11]=(w+4)&1023;}
 return 0;}
static int bar(void*v,g190_barrier b){(void)v;(void)b;return 0;}
static int now(void*v,uint64_t*t){model*x=v;*t=x->backwards?0:x->time++;return 0;}
static int waitfn(void*v,uint32_t us){model*x=v;assert(us>0&&us<=1000);x->time+=us;return 0;}
static int cancel(void*v){return ((model*)v)->cancel;}
static int hash(void*v,const uint8_t*p,size_t n,const uint8_t h[32]){(void)v;(void)p;(void)n;(void)h;return -1;}
static int fw_wr(void*v,uint32_t r,uint32_t o,uint32_t d){(void)v;(void)r;(void)o;(void)d;return -1;}
static int fw_rd(void*v,uint32_t r,uint32_t o,uint32_t*d){(void)v;(void)r;(void)o;(void)d;return -1;}
static int cfg(void*v){(void)v;return -1;}
static AdrenoHfiStartupConfig policy(void){AdrenoHfiStartupConfig c={0};c.gpu_count=c.bandwidth_count=10;c.gpu[1].hz=124800000;c.gpu[1].vote=3408385;c.ddr_count=3;c.ddr_data[1][0]=c.ddr_data[1][1]=0x600007f2;c.ddr_data[1][2]=0x60000008;return c;}
static void init(void){memset(&m,0,sizeof(m));m.time=100;m.b.shared=m.mem;m.b.iova=0x60006000;m.b.epoch=1;m.b.generation=11;m.b.phase=G190_STARTUP_COMPLETE;m.b.stage=11;m.b.startup_acked=15;m.b.reset_released=1;m.b.limits=(g190_limits){65536,10,5000000,500000,500000,3000000};m.b.ops=(g190_ops){&m,lease,stop,rd,wr,bar,now,waitfn,cancel,hash,fw_wr,fw_rd,cfg};m.mem[1]=168;m.mem[2]=6;m.mem[3]=12;m.mem[4]=m.mem[5]=3;for(unsigned q=0;q<3;q++){uint32_t*h=m.mem+6+12*q;h[0]=1;h[1]=m.b.iova+(q+1)*4096;h[2]=0xa00|q;h[3]=1024;}}
int main(void){unsigned cases=0;AdrenoHfiStartupConfig c=policy();
 init();assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_OK&&m.p.stage==6&&m.p.freq_acked&&m.p.held&&m.p.oob_may_be_held);assert(m.notifications==1&&m.requests==1&&m.ack_clears==1&&m.clears==0&&m.p.gx_before==3&&m.p.gx_after==0);assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_ARGUMENT&&m.requests==1);assert(g440_gpu_clear_stopped(&m.p,2)==G190_STATE&&m.clears==0);/* MODEL caller supplies newer stop after actual owner callback in production. */assert(g440_gpu_clear_stopped(&m.p,3)==G190_OK&&m.clears==1&&!m.p.held&&!m.p.oob_may_be_held);cases++;
 init();m.info=0x80000000u;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_BUSY&&m.notifications==0&&m.requests==0&&m.ack_clears==0);cases++;
 init();m.no_oob_ack=1;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_TIMEOUT&&m.p.freq_acked&&m.p.oob_may_be_held&&!m.p.held&&m.clears==0);cases++;
 init();m.gx_off=1;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_STATE&&m.p.ack_observed==0x80000000u&&m.p.oob_may_be_held&&!m.p.held);cases++;
 init();m.error=7;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_FW_ERROR&&m.requests==0&&!m.p.freq_acked);cases++;
 init();m.no_hfi_ack=1;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_TIMEOUT&&m.requests==0&&!m.p.freq_acked);cases++;
 init();m.cancel=1;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_CANCELLED&&m.notifications==0&&m.requests==0);cases++;
 init();m.lease_lost=1;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_LEASE_LOST&&m.notifications==0);cases++;
 init();m.b.stage=10;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_STATE&&m.notifications==0);cases++;
 init();c.gpu[1].hz=220000000;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_UNSUPPORTED&&!m.p.attempted&&m.notifications==0);cases++;
 c=policy();init();m.request_delay=20000;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_OK&&m.p.held&&m.p.request_posted_us-m.p.setup_begin_us>=20000);cases++;
 init();m.ack_read_delay=20000;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_OK&&m.p.held&&m.p.ack_sample_us-m.p.request_posted_us>=20000);cases++;
 init();m.request_delay=6000000;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_TIMEOUT&&m.p.oob_may_be_held&&!m.p.held&&m.requests==1);cases++;
 init();m.ack_read_delay=20000;m.no_oob_ack=1;assert(g440_gpu_acquire(&m.p,&m.b,&c,2)==G190_TIMEOUT&&m.p.oob_may_be_held&&!m.p.held);cases++;
 printf("{\"host_model_cases\":%u,\"native_evidence\":false,\"result\":\"pass\"}\n",cases);return 0;}
