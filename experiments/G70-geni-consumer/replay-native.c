/* SPDX-License-Identifier: MIT -- offline replay; no native hardware I/O. */
#include "g70_client_policy.h"
#include "g70_binding.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
typedef struct {const G70_REPORT*r;G70_CLOCK_RESULT*replay;uint32_t at,engine;} REPLAY;
static const G70_EVENT*Next(REPLAY*c,uint32_t kind,uint32_t reg){assert(c->at<c->r->Clock.TraceCount);const G70_EVENT*e=&c->r->Clock.Trace[c->at++];assert(e->Kind==kind&&e->Register==reg);return e;}
static int Available(void*x){(void)x;return 1;}
static int Read(void*x,uint32_t reg,uint32_t*v){*v=Next(x,1,reg)->Value;return 1;}
static int Write(void*x,uint32_t reg,uint32_t v){assert(Next(x,2,reg)->Value==v);return 1;}
static void Wait(void*x){assert(Next(x,3,1)->Value==1);}
static int Engine(void*x,uint32_t reg,uint32_t*v){REPLAY*c=x;assert(c->replay->Active&&c->replay->Phase==4&&reg==c->engine%10&&c->engine<20);*v=c->engine++<10?c->r->Probe.First[reg]:c->r->Probe.Second[reg];return 1;}
static void Packet(const char*p,G70_REPORT*r){FILE*f=fopen(p,"rb");assert(f&&fread(r,1,sizeof(*r),f)==sizeof(*r)&&fgetc(f)==EOF&&!fclose(f));}
int main(int argc,char**argv){assert(argc==3);G70_REPORT before,after;Packet(argv[1],&before);Packet(argv[2],&after);assert(G70ClientReadyForCycle(&before,sizeof(G70ExpectedDsdt)));assert(G70ClientCycleComplete(&after,sizeof(G70ExpectedDsdt),after.Clock.Nonce));assert(!memcmp(&before,&after,288));G70_CLOCK_RESULT clock={0};G70_PROBE_RESULT probe={0};REPLAY c={&after,&clock,0,0};G70_CONSUMER_IO io={{&c,Available,Read,Write,Wait},Engine};assert(G70Consume(&io,&clock,&probe,after.Clock.Nonce));assert(c.at==after.Clock.TraceCount&&c.engine==20&&!memcmp(&clock,&after.Clock,sizeof(clock))&&!memcmp(&probe,&after.Probe,sizeof(probe)));printf("{\"passed\":true,\"policy_accepted\":true,\"clock_and_probe_bytes_replayed_identically\":true,\"engine_reads_replayed_with_active_clock_lease\":20,\"native_hardware_operations\":0}\n");return 0;}
