/* Actual validator over frozen native captures plus explicitly mutated data.
 * Clock/health changes here are models, never new physical observations. */
#include "health_capture.h"
#include "health_layout.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned Cases;static uint8_t*C,*G,*OriginalC,*OriginalG;
static uint32_t U32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t U64(const uint8_t*p){return U32(p)|(uint64_t)U32(p+4)<<32;}
static void P32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void P64(uint8_t*p,uint64_t v){P32(p,(uint32_t)v);P32(p+4,(uint32_t)(v>>32));}
static void Load(const char*path,uint8_t*b,size_t n){FILE*f=fopen(path,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF&&!fclose(f));}
static void Reset(void){memcpy(C,OriginalC,CH_CONFIG_BYTES);memcpy(G,OriginalG,CH_GAUGE_BYTES);}
static void Check(uint32_t expected,uint32_t role,uint64_t nonce,uint64_t now,uint64_t oldNonce,uint64_t oldTime)
{
 CH_HEALTH h;memset(&h,0xff,sizeof(h));uint32_t code=CHValidate(C,CH_CONFIG_BYTES,G,CH_GAUGE_BYTES,nonce,now,oldNonce,oldTime,role,&h);
 if(code!=expected)fprintf(stderr,"case%u role%u code%u expected%u\n",Cases,role,code,expected);
 assert(code==expected);if(code){const CH_HEALTH zero={0};assert(!memcmp(&h,&zero,sizeof(h)));}
 else assert(h.Nonce==nonce&&h.FloatMv>=4470&&h.FastMa==300&&h.VoltageMv[0]>=3250&&h.VoltageMv[1]>=3250);
 Cases++;
}
static void GaugeWord(unsigned gauge,unsigned word,uint32_t value)
{
 unsigned index=gauge*10+word;P32(G+120+80+4*index,value);
 unsigned rx=0;uint32_t count=U32(G+120+32);
 for(unsigned i=0;i<count;i++){
  uint8_t*t=G+120+G178_GAUGE_TRACE+16*i;
  if(U32(t)==1&&(U32(t+4)&4095)==0x780){if(rx==index){P32(t+8,value);return;}rx++;}
 }
 assert(0);
}
int main(int argc,char**argv)
{
 assert(argc==13);C=malloc(CH_CONFIG_BYTES+1);G=malloc(CH_GAUGE_BYTES+1);OriginalC=malloc(CH_CONFIG_BYTES);OriginalG=malloc(CH_GAUGE_BYTES);assert(C&&G&&OriginalC&&OriginalG);
 /* argv pairs: preFV,postFV,initialoff,earlyon,lateon,finaloff. */
 for(unsigned i=0;i<6;i++){
  Load(argv[1+2*i],C,CH_CONFIG_BYTES);Load(argv[2+2*i],G,CH_GAUGE_BYTES);
  uint64_t nonce=U64(G+80),now=U64(G+56)+100000;
  Check(i==0?CH_PROFILE:CH_OK,CH_OBSERVE,nonce,now,0,0);
  Check(i<2?CH_OK:CH_STATE,CH_BEFORE_FV,nonce,now,0,0);
  Check(i==0?CH_PROFILE:i==1?CH_OK:CH_STATE,CH_BEFORE_RESTART,nonce,now,0,0);
  Check(i==0?CH_PROFILE:(i==3||i==4)?CH_OK:CH_STATE,CH_RENEW,nonce,now,0,0);
 }
 Load(argv[7],OriginalC,CH_CONFIG_BYTES);Load(argv[8],OriginalG,CH_GAUGE_BYTES);Reset();
 uint64_t nonce=U64(G+80),now=U64(G+56)+100000;CH_HEALTH h;
 const size_t lens[]={0,1,79,1095,1097,279879,279881};
 for(unsigned i=0;i<sizeof(lens)/sizeof(lens[0]);i++){
  assert(CHValidate(C,lens[i],G,CH_GAUGE_BYTES,nonce,now,0,0,CH_RENEW,&h)==CH_ARGUMENT);Cases++;
  assert(CHValidate(C,CH_CONFIG_BYTES,G,lens[i],nonce,now,0,0,CH_RENEW,&h)==CH_ARGUMENT);Cases++;
 }
 Check(CH_ARGUMENT,CH_RENEW,0,now,0,0);Check(CH_ARGUMENT,4,nonce,now,0,0);
 Check(CH_NONCE,CH_RENEW,nonce,now,nonce,0);Check(CH_FRESHNESS,CH_RENEW,nonce,now,0,U64(G+56));
 Check(CH_FRESHNESS,CH_RENEW,nonce,U64(G+56)-1,0,0);Check(CH_FRESHNESS,CH_RENEW,nonce,now+CH_FRESH_100NS,0,0);
 for(unsigned which=0;which<2;which++)for(unsigned at=0;at<=52;at+=4){
  Reset();uint8_t*b=which?G:C;P32(b+at,U32(b+at)^1);Check(CH_IDENTITY,CH_RENEW,nonce,now,0,0);
 }
 for(unsigned which=0;which<2;which++){Reset();uint8_t*b=which?G:C;P64(b+80,nonce^1);Check(CH_NONCE,CH_RENEW,nonce,now,0,0);}
 Reset();P64(C+112,U64(C+104)-1);Check(CH_FRESHNESS,CH_RENEW,nonce,now,0,0);
 Reset();P64(C+104,U64(G+56)-CH_PAIR_100NS-1);Check(CH_FRESHNESS,CH_RENEW,nonce,now,0,0);
 const unsigned cbad[]={92,96,100,120,124,128,136,140,148,152,156,160,164};
 for(unsigned i=0;i<sizeof(cbad)/sizeof(cbad[0]);i++){Reset();P32(C+cbad[i],U32(C+cbad[i])^1);Check(CH_CONFIG_RESULT,CH_RENEW,nonce,now,0,0);}
 for(unsigned offset=0;offset<40;offset+=4){
  if(offset==16||offset==20)continue;
  Reset();unsigned at=120+216+7*40+offset;P32(C+at,U32(C+at)^1);Check(CH_CONFIG_TRACE,CH_RENEW,nonce,now,0,0);
 }
 const unsigned gbad[]={96,100,104,108,112,116,120,124,128,132,136,140,144,148,156,168,172,176,180,120+160+4,120+160+20,120+8888+24};
 for(unsigned i=0;i<sizeof(gbad)/sizeof(gbad[0]);i++){Reset();P32(G+gbad[i],U32(G+gbad[i])^1);Check(CH_GAUGE_RESULT,CH_RENEW,nonce,now,0,0);}
 Reset();P32(G+120+80+12,4000);Check(CH_GAUGE_TRACE,CH_RENEW,nonce,now,0,0); /* value/trace mismatch */
 const struct{unsigned word;uint32_t value,expected;}bad[]={
  {0,0x6003,CH_GAUGE_DATA},{1,0x0601,CH_GAUGE_DATA},{2,0x0201,CH_GAUGE_DATA},
  {3,2930,CH_TEMPERATURE},{3,3132,CH_TEMPERATURE},{4,3249,CH_VOLTAGE},{4,4301,CH_VOLTAGE},
  {4,3800,CH_VOLTAGE},{8,501,CH_CURRENT},{8,65035,CH_CURRENT},{9,101,CH_GAUGE_DATA},{5,0x101,CH_STATE}};
 for(unsigned gauge=0;gauge<2;gauge++)for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
  Reset();GaugeWord(gauge,bad[i].word,bad[i].value);Check(bad[i].expected,CH_RENEW,nonce,now,0,0);
 }
 for(unsigned gauge=0;gauge<2;gauge++)for(unsigned i=0;i<2;i++){
  Reset();GaugeWord(gauge,3,i?3131:2931);Check(CH_OK,CH_RENEW,nonce,now,0,0);
  Reset();GaugeWord(gauge,8,i?65036:500);Check(CH_OK,CH_RENEW,nonce,now,0,0);
 }
 Reset();Check(CH_OK,CH_RENEW,nonce,now,0,0);
 printf("{\"passed\":true,\"cases\":%u,\"frozen_native_pairs\":6,\"native_operations\":0,\"fresh_clock_and_mutations_are_models\":true}\n",Cases);
 free(C);free(G);free(OriginalC);free(OriginalG);return 0;
}
