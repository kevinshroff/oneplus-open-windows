// SPDX-License-Identifier: MIT
// Replay captured native register results through the actual portable core.
// This is an offline check of captured bytes, never another hardware attempt.
#include "g69_client_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef struct { const G69_CLOCK_RESULT *r; uint32_t at; } REPLAY;
static const G69_EVENT *next(REPLAY *c,uint32_t kind,uint32_t reg) {
 assert(c->at<c->r->TraceCount);
 const G69_EVENT *e=&c->r->Trace[c->at++];
 assert(e->Kind==kind && e->Register==reg);return e;
}
static int available(void *p) {(void)p;return 1;}
static int read_reg(void *p,uint32_t id,uint32_t *v) {
 *v=next(p,1,id)->Value;return 1;
}
static int write_reg(void *p,uint32_t id,uint32_t v) {
 assert(next(p,2,id)->Value==v);return 1;
}
static void wait_us(void *p) {assert(next(p,3,1)->Value==1);}
static void packet(const char *p,G69_REPORT *r) {
 FILE *f=fopen(p,"rb");assert(f);assert(fread(r,1,sizeof(*r),f)==sizeof(*r));
 assert(fgetc(f)==EOF);assert(fclose(f)==0);
}
int main(int argc,char **argv) {
 assert(argc==3);G69_REPORT before,after;packet(argv[1],&before);packet(argv[2],&after);
 assert(G69ClientReadyForCycle(&before,742));
 int accepted=G69ClientCycleComplete(&after,742,after.Clock.Nonce);
 assert(after.Clock.Restored==1 && !after.Clock.RestoreError && !after.Clock.DirtyMask && !after.Clock.Active);
 assert(accepted==(after.Clock.Code==0));
 assert(after.Clock.Code==0 || after.Clock.Code==5);
 assert(memcmp(&before,&after,208)==0);
 REPLAY c={&after.Clock,0};G69_CLOCK_RESULT replay={0};
 G69_CLOCK_IO io={&c,available,read_reg,write_reg,wait_us};
 int acquired=G69ClockAcquire(&io,&replay,after.Clock.Nonce);
 if(acquired)assert(G69ClockRelease(&io,&replay,after.Clock.Nonce));
 assert(acquired==accepted);
 assert(c.at==after.Clock.TraceCount);
 assert(memcmp(&replay,&after.Clock,sizeof(replay))==0);
 printf("{\"passed\":true,\"actual_core_replays_all_native_events_byte_identically\":true,\"policy_accepted\":%s,\"native_hardware_operations\":0}\n",accepted?"true":"false");
 return 0;
}
