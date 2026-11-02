/* Exercise the actual fixed-read core. Register transitions are explicit models,
 * with native533's nonzero status/zero word count, not a simulated physical fix. */
#include "register-model.h"
int main(void){
 GAUGE_MODEL*m=calloc(1,sizeof(*m));G104_RESULT*r=calloc(1,sizeof(*r));assert(m&&r);unsigned cases=0;
 const uint32_t bits[]={0x02000000u,0x20000000u,0x80000000u,0xa0000000u};
 for(unsigned n=0;n<46;n++)if(G104Kind(n)==2)for(unsigned b=0;b<4;b++)for(unsigned polls=1;polls<=8;polls+=7){
  GaugeModelReset(m);memset(r,0,sizeof(*r));m->TransientCmd=n+1;m->TransientBits=bits[b];m->TransientReads=polls;
  G104_IO io={m,GaugeModelRead,GaugeModelWrite,GaugeModelAvailable,GaugeModelNow,GaugeModelDelay};G104Identify(&io,r);
#ifdef EXPECT_OLD_FAILURE
  assert(r->Code==G104_FIFO_ERROR&&r->Commands==n+1&&r->Completed==n);
#else
  assert(!r->Code&&!r->Uncertain&&r->Commands==46&&r->Completed==46&&r->QueryMask==0xfffff&&r->RestoredMask==3&&!m->TransientReads);
#endif
  cases++;
 }
#ifndef EXPECT_OLD_FAILURE
 /* Malformed complete words are still refused; a permanently empty response
  * remains bounded by the existing timeout and cleanup. */
 for(unsigned n=0;n<46;n++)if(G104Kind(n)==2){
  GaugeModelReset(m);memset(r,0,sizeof(*r));m->TransientCmd=n+1;m->TransientBits=0xb0000001u;m->TransientReads=1;
  G104_IO io={m,GaugeModelRead,GaugeModelWrite,GaugeModelAvailable,GaugeModelNow,GaugeModelDelay};G104Identify(&io,r);assert(r->Code==G104_FIFO_ERROR);cases++;
 }
 GaugeModelReset(m);memset(r,0,sizeof(*r));m->TransientCmd=17;m->TransientBits=0x02000000u;m->TransientReads=300;
 G104_IO io={m,GaugeModelRead,GaugeModelWrite,GaugeModelAvailable,GaugeModelNow,GaugeModelDelay};G104Identify(&io,r);assert(r->Code==G104_TIMEOUT&&m->TransientReads==44);cases++;
#endif
 printf("{\"passed\":true,\"RX_transition_cases\":%u,\"native_operations\":0}\n",cases);free(r);free(m);
}
