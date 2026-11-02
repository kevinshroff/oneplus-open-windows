#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "g735_smmu_identity.h"
typedef struct {uint32_t a,v;} EVENT;
static uint32_t mem[G735_APERTURE/4];static EVENT events[32];
static unsigned writes,reads;static uint64_t bad_read,bad_write;static int corrupt,sync_busy;
static int read32(void*c,uint64_t a,uint32_t*v){
 (void)c;reads++;if(a==bad_read||a<G735_BASE||a>=G735_BASE+G735_APERTURE)return 1;
 if(a==G735_BASE+0x74&&sync_busy){*v=1;return 0;}
 *v=mem[(a-G735_BASE)/4];return 0;
}
static int write32(void*c,uint64_t a,uint32_t v){
 (void)c;if(a==bad_write)return 1;
 assert(writes<32);events[writes++]=(EVENT){(uint32_t)(a-G735_BASE),v};
 mem[(a-G735_BASE)/4]=v^((corrupt&&a==G735_BASE+0xc00)?1u:0u);return 0;
}
static G403_IO io={0,read32,write32};
static void reset(void){
 memset(mem,0,sizeof(mem));mem[0x20/4]=0x4c017e69;mem[0x24/4]=0x60000046;
 for(unsigned n=0;n<105;n++)mem[(0xc00+4*n)/4]=0x20000;
 writes=reads=0;bad_read=bad_write=0;corrupt=sync_busy=0;
}
static void geometry(void){
 G735_RESULT r;G735Init(&r);
 assert(!G735Geometry(0x4c017e69,0x60000046,&r));
 assert(r.NumSmr==105&&r.NumCb==70&&r.PageSize==4096&&r.Pages==128);
 assert(r.CbBase==0x15080000&&r.Span==0xc6000);
 G735Init(&r);assert(G735Geometry(0x4c017e69,0xe0000046,&r)); /* 64K aperture overflow */
 G735Init(&r);assert(G735Geometry(0x4c017f69,0x60000046,&r)); /* EXIDS unsupported */
 G735Init(&r);assert(G735Geometry(0x4c017e00,0x60000046,&r)); /* no groups */
}
static void success(void){
 reset();G735_RESULT r;G735Init(&r);assert(!G735PrepareIdentity(&io,&r));
 assert(r.Prepared&&r.Writes==11&&writes==11&&r.RetainUntilReset);
 assert(r.Stream[0].Cb==1&&r.Stream[0].CbAddress==0x15081000);
 assert(r.Stream[1].Cb==2&&r.Stream[1].CbAddress==0x15082000);
 assert(r.Stream[0].S2cr==1&&r.Stream[1].S2cr==2);
 assert(events[0].a==0x1804&&events[1].a==0x1004&&events[2].a==0x81000);
 assert(events[3].a==0xc00&&events[3].v==1&&events[4].a==0x800&&events[4].v==0x80001401);
 assert(events[10].a==0x70);
 unsigned prior=writes;assert(G735PrepareIdentity(&io,&r)&&writes==prior); /* no second allocation */
}
static void full_scan_and_ownership(void){
 reset();mem[(0x800+4*104)/4]=0x80011400; /* masked match outside old first16 capture */
 G735_RESULT r;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&r.Stage==2&&r.Code==2&&!writes);
 reset();mem[(0x800+4*104)/4]=0x00011400; /* staged masked overlap also reserved */
 G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&r.Code==2&&!writes);
 reset();bad_read=G735_BASE+0x800+4*100;
 G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes);
 reset();mem[0x81000/4]=0xe0; /* nonzero bank must not be reused */
 G735Init(&r);assert(!G735PrepareIdentity(&io,&r)&&r.Stream[0].Cb==2);
 reset();mem[0xc00/4]=0; /* staged/owned invalid slot, not reset default */
 G735Init(&r);assert(!G735PrepareIdentity(&io,&r)&&r.Stream[0].Slot==1);
 reset();mem[0xc00/4]=1; /* invalid SMR, staged translate binding owns CB1 */
 G735Init(&r);assert(!G735PrepareIdentity(&io,&r)&&r.Stream[0].Slot==1&&r.Stream[0].Cb==2);
 assert(r.Stream[1].Cb==3&&mem[0x81000/4]==0);
}
static void high_banks(void){
 reset();
 for(unsigned n=0;n<64;n++){mem[(0x800+4*n)/4]=0x80002000+n;mem[(0xc00+4*n)/4]=n;}
 G735_RESULT r;G735Init(&r);assert(!G735PrepareIdentity(&io,&r));
 assert(r.Stream[0].Cb==64&&r.Stream[1].Cb==65);
 assert(r.Stream[0].CbAddress==0x150c0000&&r.Stream[0].S2cr==64);
}
static void failure_closes_gate(void){
 reset();corrupt=1;G735_RESULT r;G735Init(&r);
 assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&r.RetainUntilReset&&r.Stage==4&&r.Code==2);
 assert(writes==4&&!(mem[0x800/4]>>31)); /* no valid stream installed */
 assert(r.LastAddress==G735_BASE+0xc00&&r.LastExpected==1&&r.LastReadbackValid&&r.LastReadback==0);
 reset();bad_write=G735_BASE+0x1804;G735Init(&r);
 assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&!writes&&r.AttemptedWrites==1);
 reset();sync_busy=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&r.Stage==5);
 reset();mem[0x48/4]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes&&r.Code==6);
 reset();mem[0]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes); /* CLIENTPD */
}
int main(void){geometry();success();full_scan_and_ownership();high_banks();failure_closes_gate();puts("5 identity test groups passed");return 0;}
