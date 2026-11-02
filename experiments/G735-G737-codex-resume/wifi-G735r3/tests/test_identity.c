#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "g735_smmu_identity.h"
typedef struct {uint32_t a,v;} EVENT;
static uint32_t mem[G735_APERTURE/4];static EVENT events[64];
static unsigned writes,reads;static int mutate_after_write;static uint64_t bad_read,bad_write;static int corrupt,sync_busy;
static int read32(void*c,uint64_t a,uint32_t*v){
 (void)c;reads++;if(a==bad_read||a<G735_BASE||a>=G735_BASE+G735_APERTURE)return 1;
 if(a==G735_BASE+0x74&&sync_busy){*v=1;return 0;}
 *v=mem[(a-G735_BASE)/4];return 0;
}
static int write32(void*c,uint64_t a,uint32_t v){
 (void)c;if(a==bad_write)return 1;
 assert(writes<64);events[writes++]=(EVENT){(uint32_t)(a-G735_BASE),v};
 mem[(a-G735_BASE)/4]=v^((corrupt&&a==G735_BASE+0xc00)?1u:0u);
 if(mutate_after_write&&writes==1){if(mutate_after_write==1)mem[0x82030/4]=0x123;else mem[(0xc00+4*104)/4]=2;}
 return 0;
}
static G403_IO io={0,read32,write32};
static void reset(void){
 memset(mem,0,sizeof(mem));mem[0x20/4]=0x4c017e69;mem[0x24/4]=0x60000046;
 for(unsigned n=0;n<105;n++)mem[(0xc00+4*n)/4]=0x20000;
 for(unsigned n=0;n<70;n++)mem[(0x80000+0x1000*n+4)/4]=3;
 writes=reads=0;bad_read=bad_write=0;corrupt=sync_busy=mutate_after_write=0;
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
 assert(r.Prepared&&r.Writes==31&&writes==31&&r.RetainUntilReset);
 assert(r.Stream[0].Cb==1&&r.Stream[0].CbAddress==0x15081000);
 assert(r.Stream[1].Cb==2&&r.Stream[1].CbAddress==0x15082000);
 assert(r.Stream[0].S2cr==1&&r.Stream[1].S2cr==2);
 assert(events[0].a==0x81000&&events[0].v==0);
 assert(events[10].a==0x1804&&events[11].a==0x1004&&events[12].a==0x81000);
 assert(events[13].a==0xc00&&events[13].v==1&&events[14].a==0x800&&events[14].v==0x80001401);
 assert(events[30].a==0x70&&r.Revalidations==33);
 for(unsigned n=0;n<writes;n++){assert(events[n].a!=0x81004&&events[n].a!=0x82004&&events[n].a!=0x81058&&events[n].a!=0x82058);}
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
 assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&r.RetainUntilReset&&r.Stage==4&&r.Code==4);
 assert(writes==14&&!(mem[0x800/4]>>31)); /* no valid stream installed */
 assert(r.LastAddress==G735_BASE+0xc00&&r.LastExpected==1&&r.LastReadbackValid&&r.LastReadback==0);
 reset();bad_write=G735_BASE+0x81000;G735Init(&r);
 assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&!writes&&r.AttemptedWrites==1);
 reset();sync_busy=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&r.Stage==5);
 reset();mem[0x48/4]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes&&r.Code==6);
 reset();mem[0]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes); /* CLIENTPD */
}
static void actual_unknown_fixture(void){
 reset();
 for(unsigned n=0;n<70;n++)mem[(0x80000+0x1000*n+4)/4]=0; /* only observed9/10 admitted */
 const uint32_t smrs[9]={0x80000060,0x80000540,0x80000080,0x80000040,0x80021c00,0x80000480,0x80000540,0x80000080,0x80000480};
 for(unsigned n=0;n<9;n++){mem[(0x800+4*n)/4]=smrs[n];mem[(0xc00+4*n)/4]=n;}
 const uint32_t cb9[12]={0x3bbde302,3,0x00010066,0xfe8a8cca,0xa64f6358,0xf38ee381,0xb27cf5d3,0x3b397317,0xfbfdefed,0xdebd71c4,0x1dafdd9f,0};
 const uint32_t cb10[12]={0x3bdfe118,3,0x4002c076,0x42eeccab,0x62daf3ab,0xb627bb6c,0xdfa366fa,0x7f851ebd,0xddbddf3c,0xf2b9fb3b,0xc08db538,0};
 const unsigned off[12]={0,4,0x10,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,0x58};
 for(unsigned n=0;n<12;n++){mem[(0x89000+off[n])/4]=cb9[n];mem[(0x8a000+off[n])/4]=cb10[n];}
}
static void observed_disabled_profile(void){
 actual_unknown_fixture();G735_RESULT r;G735Init(&r);assert(!G735PrepareIdentity(&io,&r));
 assert(r.Stream[0].Cb==9&&r.Stream[1].Cb==10&&writes==31);
 assert(r.Stream[0].Before.Sctlr==0x3bbde302&&r.Stream[1].Before.Ttbr0Lo==0x42eeccab);
 for(unsigned k=0;k<2;k++){
  G735_STREAM*s=&r.Stream[k];assert(s->BeforeValid&&s->AfterValid);
  assert(s->After.Sctlr==0xe0&&s->After.Actlr==3&&s->After.Cbar==0x1f000&&s->After.Cba2r==1);
  for(unsigned n=2;n<12;n++)assert(s->After.Word[n]==0);
 }
 for(unsigned bit=0;bit<3;bit++){
  actual_unknown_fixture();mem[0x89000/4]|=(bit==0?1u:1u<<(bit==1?5:6));G735Init(&r);
  assert(G735PrepareIdentity(&io,&r)&&!writes&&r.Stage==2&&r.Code==6);
 }
 actual_unknown_fixture();mem[(0xc00+4*104)/4]=9;G735Init(&r); /* staged invalid references CB9 */
 assert(G735PrepareIdentity(&io,&r)&&!writes&&r.Code==6);
 actual_unknown_fixture();mem[0x89058/4]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes);
 actual_unknown_fixture();mem[0x1800/4+9]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes);
 actual_unknown_fixture();mem[0x1000/4+9]=0x1f000;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes);
 actual_unknown_fixture();mem[0x89004/4]=1;G735Init(&r);assert(G735PrepareIdentity(&io,&r)&&!writes);
}
static void revalidation_stops_foreign_changes(void){
 for(int mode=1;mode<=2;mode++){
  reset();mutate_after_write=mode;G735_RESULT r;G735Init(&r);
  assert(G735PrepareIdentity(&io,&r)&&!r.Prepared&&writes==1&&r.RetainUntilReset);
  assert(r.Stage==4&&r.Code==2);
  if(mode==1)assert(r.Stream[1].AfterValid&&r.Stream[1].After.Tcr==0x123);
 }
}
int main(void){geometry();success();full_scan_and_ownership();high_banks();failure_closes_gate();observed_disabled_profile();revalidation_stops_foreign_changes();puts("7 identity test groups passed");return 0;}
