/* Real extracted production executor + actual tables; explicit CPU actor. */
#include "host.h"
#include "g456_tables.h"
#include "g456_secvid_zero.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static G433_RUNTIME run;static G321_RUNTIME gmu;static OGO_CONTEXT owner;
static ULONG gpu[65536],core[65536];
static struct {ULONG bank,off,value;} writes[256],success[256];
static unsigned nw,ns,reads,ahbs,barriers,deny,failwrite,dropat,failbarrier;
static const ULONG secvid[]={0x3e00c,0x3e000,0x3e004,0x3e008};
ULONG KeGetCurrentIrql(void){return 0;}
ULONG DbgPrintEx(ULONG id,ULONG level,const char *fmt,...){(void)id;(void)level;(void)fmt;return 0;}
NTSTATUS OgoCpCurrent(OGO_CONTEXT *o){assert(o==&owner);return deny?STATUS_DEVICE_NOT_READY:0;}
NTSTATUS G482CoreRead(void *io,ULONG off,PULONG v){assert(io==&owner&&!(off&3)&&off/4<65536);*v=core[off/4];return 0;}
static NTSTATUS store(ULONG bank,ULONG off,ULONG v){
 assert(!(off&3)&&off/4<65536&&nw<256);
 writes[nw].bank=bank;writes[nw].off=off;writes[nw++].value=v;
 if(bank==0){for(unsigned j=0;j<4;j++)if(off==secvid[j]){
  /* Every existing zero admission must precede the first parity store. */
  for(unsigned k=0;k<4;k++){
   unsigned seen=0;for(unsigned i=0;i<run.Hwinit.Count;i++){
    const G456_ACCESS *a=&run.Hwinit.Access[i];
    if(!a->Bank&&!a->Operation&&a->ByteOffset==secvid[k]&&!a->Value&&a->Status==0)seen++;
   }assert(seen==1);
  }
  assert(run.Hwinit.Stage==2&&v==0);
 }}
 if(failwrite==nw)return STATUS_ACCESS_DENIED;
 (bank?core:gpu)[off/4]=v;return 0;
}
NTSTATUS G482CoreWrite(void *io,ULONG off,ULONG v){assert(io==&owner);return store(1,off,v);}
static NTSTATUS rd(void *o,ULONG off,PULONG v){assert(o==&owner&&!(off&3)&&off/4<65536);reads++;*v=gpu[off/4];return 0;}
static NTSTATUS wr(void *o,ULONG off,ULONG v){assert(o==&owner);return store(0,off,v);}
static NTSTATUS ahb(void *o,PULONG v){assert(o==&owner);*v=(++ahbs==dropat);return 0;}
static int barrier(void *o,int kind){assert(o==&owner&&kind==G190_COMPLETE);return ++barriers==failbarrier;}
static void init(void){
 memset(&run,0,sizeof(run));memset(&gmu,0,sizeof(gmu));memset(gpu,0,sizeof(gpu));memset(core,0,sizeof(core));
 nw=reads=ahbs=barriers=deny=failwrite=dropat=failbarrier=0;
 owner.RunId=1;gmu.Generation=run.Generation=7;run.Gmu=&gmu;
 gmu.Io=gmu.Owner.Cookie=gmu.Core.ops.cookie=&owner;gmu.Core.ops.barrier=barrier;
 gmu.Core.phase=G190_STARTUP_COMPLETE;gmu.Inputs=(g196_preflight){519,0x20000,2};
 run.Power.held=1;run.Gpu.Board=(G456_FACTS){7,0x70201,8,1,1};
 run.Gpu.ReadGpuRegister=rd;run.Gpu.WriteGpuRegister=wr;run.Gpu.AhbFenceStatus=ahb;
 gpu[G456_RB_CMP_DBG_ECO_CNTL]=0x200;
}
int main(void){unsigned cases=0;init();
 assert(G456ConfigureGpuStopped(&run)==0&&run.Hwinit.Complete);cases++;
#if OGO_GPU_SECVID_ZERO_STORES
 assert(nw==144&&run.Hwinit.Writes==144&&run.Hwinit.Reads==23);
 for(unsigned i=0;i<4;i++)assert(!writes[i].bank&&writes[i].off==secvid[i]&&!writes[i].value);
#else
 assert(nw==140&&run.Hwinit.Writes==140&&run.Hwinit.Reads==23);
 for(unsigned i=0;i<nw;i++)for(unsigned j=0;j<4;j++)assert(writes[i].bank||writes[i].off!=secvid[j]);
#endif
 ns=nw;memcpy(success,writes,sizeof(success));
 unsigned before=nw;assert(G456ConfigureGpuStopped(&run)==STATUS_DEVICE_BUSY&&nw==before);cases++;
 for(unsigned i=0;i<4;i++){init();gpu[secvid[i]/4]=1;assert(G456ConfigureGpuStopped(&run)==STATUS_NOT_SUPPORTED&&nw==0&&!run.Hwinit.Retained&&!run.Hwinit.Complete);cases++;}
 init();deny=1;assert(G456ConfigureGpuStopped(&run)==STATUS_DEVICE_NOT_READY&&nw==0);cases++;
 init();run.Gpu.Board.SourceProfile=0;assert(G456ConfigureGpuStopped(&run)==STATUS_NOT_SUPPORTED&&nw==0&&reads==0);cases++;
#if OGO_GPU_SECVID_ZERO_STORES
 for(unsigned i=1;i<=4;i++){
  init();failwrite=i;assert(G456ConfigureGpuStopped(&run)==STATUS_ACCESS_DENIED&&nw==i&&run.Hwinit.Retained&&!run.Hwinit.Complete);cases++;
  init();failbarrier=i;assert(G456ConfigureGpuStopped(&run)==STATUS_DEVICE_NOT_READY&&nw==i&&run.Hwinit.Retained&&!run.Hwinit.Complete);cases++;
 }
 for(unsigned i=1;i<=8;i++){
  init();dropat=i;assert(G456ConfigureGpuStopped(&run)==STATUS_DEVICE_NOT_READY&&nw==i/2&&!run.Hwinit.Complete);
  assert(run.Hwinit.Retained==(i>1));cases++;
 }
#endif
 printf("{\"cases\":%u,\"native_evidence\":false,\"writes\":[",cases);
 for(unsigned i=0;i<ns;i++)printf("%s[%u,%u,%u]",i?",":"",success[i].bank,success[i].off,success[i].value);
 puts("]}");
}
