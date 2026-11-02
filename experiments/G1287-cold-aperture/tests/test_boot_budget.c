/* Actual generic backend, bounded callback/time actors, not hardware proof. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "g190_backend.h"
static g190_backend b;static _Alignas(4096) uint32_t queue[4096];static uint32_t regs[0x30000/4];static uint64_t now_us,board_us,ready_us,release_us;static unsigned now_calls,resetstores,configstores,consumed,mode;static int revoked,cancel;
static int lease(void*p,uint64_t g){(void)p;return revoked||g!=1;}static int stopped(void*p,uint64_t s,uint64_t g){(void)p;return s!=1||g!=1;}
static int rd(void*p,uint32_t o,uint32_t*v){(void)p;assert(!(o&3)&&o<sizeof(regs));if(mode==4&&o==G190_DTCM_VERSION)now_us+=G190_PREBOOT_US;if(mode==5&&o==G190_HFI_QTBL_INFO&&configstores)now_us+=G190_PREBOOT_US;*v=regs[o/4];if(o==G190_FW_RESULT&&resetstores&&now_us-release_us>=ready_us)*v=0x100;if(mode==7&&o==G190_HFI_QTBL_ADDR&&configstores)*v^=4096;return 0;}
static int wr(void*p,uint32_t o,uint32_t v){(void)p;assert(!(o&3)&&o<sizeof(regs));if(mode==10&&o==G190_HFI_QTBL_ADDR)return -1;regs[o/4]=v;if(o==G190_CM3_RESET&&v==0){resetstores++;release_us=now_us;}else if(o==G190_FW_RESULT||o==G190_BOOT_CONFIG||o==G190_HFI_QTBL_ADDR||o==G190_HFI_QTBL_INFO){configstores++;if(mode==3&&o==G190_FW_RESULT)now_us+=G190_PREBOOT_US;}return 0;}
static int barrier(void*p,g190_barrier k){(void)p;(void)k;return 0;}static int clockfn(void*p,uint64_t*v){(void)p;now_calls++;if(mode==6&&now_calls==6)now_us+=G190_PREBOOT_US;*v=mode==8&&now_calls==3?0:++now_us;return 0;}static int waitfn(void*p,uint32_t u){(void)p;now_us+=u;return 0;}static int cancelled(void*p){(void)p;return cancel;}static int hash(void*p,const uint8_t*d,size_t n,const uint8_t e[32]){(void)p;(void)d;(void)n;(void)e;return 0;}static int fw(void*p,uint32_t r,uint32_t o,uint32_t v){(void)p;(void)r;(void)o;(void)v;return 0;}static int fr(void*p,uint32_t r,uint32_t o,uint32_t*v){(void)p;(void)r;(void)o;*v=0;return 0;}
static int board(void*p){(void)p;consumed=1;now_us+=board_us;if(mode==9)revoked=1;if(mode==11)cancel=1;if(mode==12)regs[G190_AO_MASK/4]=0x7e;return 0;}
static void init(uint64_t setup,uint64_t ready,unsigned m){memset(&b,0,sizeof(b));memset(regs,0,sizeof(regs));now_us=0;board_us=setup;ready_us=ready;mode=m;now_calls=resetstores=configstores=consumed=0;revoked=cancel=0;regs[G190_CM3_RESET/4]=1;regs[G190_G2H_MASK/4]=UINT32_MAX;regs[G190_AO_MASK/4]=G190_AO_MASK_ALL;regs[G190_DTCM_VERSION/4]=0x40010009;
 g190_ops ops={0,lease,stopped,rd,wr,barrier,clockfn,waitfn,cancelled,hash,fw,fr,board};g190_limits lim={65536,10,5000000,500000,500000,3000000};assert(sizeof(lim)==40&&G190_PREBOOT_US==5000000);assert(g190_initialize(&b,&ops,&lim,queue,sizeof(queue),0x60006000)==G190_OK);b.epoch=b.generation=b.stop_serial=1;b.phase=G190_LOADED;}
static void failed(g190_status s,unsigned stage,unsigned checkpoint){assert(s!=G190_OK&&b.phase==G190_FAILED&&b.failure==s&&b.failure_stage==stage&&b.boot_checkpoint==checkpoint&&b.resources_must_retain);}
int main(void){unsigned cases=0;g190_status s;
 init(800000,490000,0);assert(g190_boot_firmware(&b,1)==G190_OK&&resetstores==1&&consumed&&b.phase==G190_FW_READY&&b.boot_checkpoint==G190_BOOT_READY);assert(b.preboot_board_us-b.preboot_begin_us>=800000&&b.firmware_begin_us==b.preboot_done_us&&b.last_us-b.firmware_begin_us>=490000&&b.last_us-b.firmware_begin_us<500000);cases++;
 init(4900000,490000,0);assert(g190_boot_firmware(&b,1)==G190_OK&&resetstores==1&&b.last_us-b.preboot_begin_us>G190_PREBOOT_US&&b.preboot_done_us-b.preboot_begin_us<G190_PREBOOT_US&&b.last_us-b.firmware_begin_us<500000);cases++;
 init(G190_PREBOOT_US,0,0);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_BOARD_DONE);assert(s==G190_TIMEOUT&&consumed&&!resetstores&&!b.reset_released&&!b.firmware_begin_us&&b.preboot_board_us-b.preboot_begin_us>=G190_PREBOOT_US);cases++;
 for(unsigned m=3;m<=6;m++){init(0,0,m);s=g190_boot_firmware(&b,1);unsigned point=m==3?G190_BOOT_CONFIG_POSTED:m==4?G190_BOOT_STATE_CHECKED:G190_BOOT_CONFIG_VERIFIED;failed(s,3,point);assert(s==G190_TIMEOUT&&!resetstores&&!b.reset_released&&!b.firmware_begin_us);cases++;}
 init(800000,500000,0);s=g190_boot_firmware(&b,1);failed(s,4,G190_BOOT_RESET_BOUNDARY);assert(s==G190_TIMEOUT&&resetstores==1&&b.reset_released&&consumed&&b.last_us-b.firmware_begin_us>=500000);cases++;
 init(0,0,7);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_CONFIG_POSTED);assert(s==G190_STATE&&!resetstores);cases++;
 init(0,0,8);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_STATE_CHECKED);assert(s==G190_CLOCK&&!resetstores);cases++;
 init(0,0,9);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_BOARD_DONE);assert(s==G190_LEASE_LOST&&!resetstores&&!configstores);cases++;
 init(0,0,10);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_STATE_CHECKED);assert(s==G190_IO&&!resetstores);cases++;
 init(0,0,11);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_BOARD_DONE);assert(s==G190_CANCELLED&&!resetstores&&!configstores);cases++;
 init(0,0,12);s=g190_boot_firmware(&b,1);failed(s,3,G190_BOOT_BOARD_DONE);assert(s==G190_STATE&&!resetstores);cases++;
 printf("PASS %u actual backend boot-budget cases: separate5s preboot/unchanged500ms ready, >500msboard admitted, allpreboot checkpoints bounded, noreset onexpiry, lateFWretained, state/clock/lease/cancel/write refusal unchanged; hostactor only\n",cases);return 0;}
