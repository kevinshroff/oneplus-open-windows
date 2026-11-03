/* HOST ONLY: actual G433 source with explicit mock IO; no native ABI evidence. */
#include "g433_cp.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
static uint32_t reg[65536];static unsigned zero,release,wp,pub,waits,failzero;static uint64_t clockus;
static int good(void*x){(void)x;return 0;}static int readreg(void*x,uint32_t o,uint32_t*v){(void)x;*v=reg[o/4];return 0;}
static int writefn(void*x,uint32_t o,uint32_t v){(void)x;if(o==0x2020){assert(v==0);zero++;if(v)release++;if(failzero)return -1;}if(o==0x201c&&v)wp++;reg[o/4]=v;return 0;}
static int publish(void*x,const volatile uint32_t*p,size_t n){(void)x;assert(p&&n);pub++;return 0;}
static int acquire(void*x,volatile uint32_t*p,size_t n){(void)x;(void)p;(void)n;assert(0);return -1;}
static int now(void*x,uint64_t*v){(void)x;*v=clockus++;return 0;}static int waitfn(void*x,uint32_t u){(void)x;(void)u;waits++;return 0;}static int fence(void*x,uint32_t*v){(void)x;*v=0;return 0;}
int main(void){for(unsigned failure=0;failure<2;failure++){g433_cp c={0};g433_memory m[4];size_t bytes[]={0x8000,0x1000,0x13000,0x1000};uint64_t va[]={0xf0000000,0xf0008000,0xf0010000,0xf0030000};for(unsigned i=0;i<4;i++)m[i]=(g433_memory){calloc(1,bytes[i]),va[i],bytes[i]};failzero=failure;zero=release=wp=pub=waits=0;g433_cp_ops o={0,good,readreg,writefn,publish,acquire,good,now,waitfn,good,fence};assert(g433_cp_run(&c,&o,m,100)==(failure?G433_IO:G433_STATE));assert(zero==1&&!release&&!wp&&pub==3&&!waits&&c.stage==3&&c.poisoned&&c.may_run&&!c.issued&&!c.completed&&!c.polls);for(unsigned i=0;i<m[0].bytes/4;i++)assert(m[0].cpu[i]==0);assert(g433_cp_secure_begin(&c,100)==G433_STATE);assert(g433_cp_poll(&c)==G433_STATE);assert(g433_cp_run(&c,&o,m,100)==G433_ARGUMENT);assert(zero==1&&!wp);for(unsigned i=0;i<4;i++)free((void*)m[i].cpu);}puts("PASS: zero once; success/failure terminal stage3; no release/packet/doorbell/poll/retry");}
