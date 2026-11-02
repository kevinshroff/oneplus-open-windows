/* Behavior tests: owner/time/power are explicit models; fixture words are real. */
#include "battery_cache.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned Cases;
static OB_BATCH Batch(uint64_t sequence,uint64_t end){
 OB_BATCH b={0};b.OwnerEpoch=1;b.Sequence=sequence;b.OwnerQualified=b.Complete=1;b.BeginUs=end-100;b.EndUs=end;
 for(unsigned i=0;i<2;i++){const uint32_t w[10]={0x6002,0x602,0x200,3000,3800,0x181,500,1000,0,50};for(unsigned j=0;j<10;j++)b.Words[i][j]=w[j];b.PowerKnown[i]=1;b.PowerState[i]=OB_CHARGING;}
 return b;
}
static void Begin(OB_CACHE*c){uint32_t n=0;ObInitialize(c);assert(ObBeginOwner(c,1,&n)==OB_OK&&!n);}
static void Publish(OB_CACHE*c,OB_BATCH*b){uint32_t n=0;assert(ObPublish(c,b,b->EndUs,&n)==OB_OK);Cases++;}
static uint32_t Word(const unsigned char*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static void NativeWords(const char*path){
 unsigned char raw[80];FILE*f=fopen(path,"rb");assert(f&&fread(raw,1,sizeof(raw),f)==sizeof(raw)&&fgetc(f)==EOF);fclose(f);
 OB_CACHE c;OB_BATCH b=Batch(1,1000);uint32_t n=0,tag=0;OB_READING r;Begin(&c);
 for(unsigned i=0;i<2;i++){for(unsigned j=0;j<10;j++)b.Words[i][j]=Word(raw+40*i+4*j);b.PowerKnown[i]=b.PowerState[i]=b.RateKnown[i]=0;}
 b.OwnerQualified=0;assert(ObPublish(&c,&b,1000,&n)==OB_INVALID_DATA&&!c.Present);Cases++;
 /* Replayed bytes do not create a native lease. This explicit modeled lease
  * exercises cache semantics only; no installed producer supplies it yet. */
 b.Sequence=2;b.OwnerQualified=1;Publish(&c,&b);assert(ObQueryTag(&c,0,1000,&tag)==OB_OK);
 assert(ObRead(&c,0,tag,1000,&r)==OB_OK&&r.VoltageMv==3442&&r.FullMah==3097&&r.RemainingMah==45&&r.Soc==2&&r.RateMa==8&&!r.PowerKnown&&!r.RateKnown);Cases++;
 assert(ObRead(&c,1,tag,1000,&r)==OB_OK&&r.VoltageMv==3443&&r.FullMah==1359&&r.RemainingMah==8&&r.Soc==1&&!r.RateKnown);Cases++;
}
int main(int argc,char**argv){assert(argc==2);OB_CACHE c;OB_BATCH b;OB_READING r;uint32_t n=0,tag=0,old=0;
 NativeWords(argv[1]);Begin(&c);b=Batch(1,200);assert(ObPublish(&c,&b,200,&n)==OB_OK&&n==3);tag=c.LastTag;Cases++;
 b=Batch(2,400);b.PowerState[0]=b.PowerState[1]=0;assert(ObPublish(&c,&b,400,&n)==OB_OK&&n==3);Cases++;
 assert(ObSetNotify(&c,0,tag,400,OB_CHARGING,0,1000,&n)==OB_OK&&n==1);Cases++;
 assert(ObTick(&c,400,&n)==OB_OK&&!n);assert(ObSetNotify(&c,0,tag,400,0,400,600,&n)==OB_OK&&!n);Cases++;
 b=Batch(3,600);b.PowerState[0]=b.PowerState[1]=0;b.Words[0][6]=300;assert(ObPublish(&c,&b,600,&n)==OB_OK&&n==1&&!c.Notify[0].Armed);Cases++;
 assert(ObSetNotify(&c,0,tag,600,0,0,1000,&n)==OB_OK&&!n);assert(ObDisableNotify(&c,0)==OB_OK);b=Batch(4,800);b.PowerState[0]=b.PowerState[1]=0;b.Words[0][6]=900;assert(ObPublish(&c,&b,800,&n)==OB_OK&&!n);Cases++;
 b=Batch(5,1000);b.PowerState[0]=OB_CRITICAL;b.PowerState[1]=0;assert(ObPublish(&c,&b,1000,&n)==OB_OK&&n==1);Cases++;
 b=Batch(6,1200);b.PowerKnown[0]=b.PowerKnown[1]=0;b.PowerState[0]=b.PowerState[1]=0;assert(ObPublish(&c,&b,1200,&n)==OB_OK&&n==3);Cases++;
 assert(ObSetNotify(&c,0,tag,1200,0,0,1000,&n)==OB_NOT_READY&&!n);Cases++;
 b=Batch(7,1400);b.PowerState[0]=b.PowerState[1]=OB_DISCHARGING;b.Words[0][8]=8;assert(ObPublish(&c,&b,1400,&n)==OB_OK&&n==3);assert(ObRead(&c,0,tag,1400,&r)==OB_OK&&!r.RateKnown);Cases++;
 b=Batch(8,1600);b.RateKnown[0]=1;b.Words[0][8]=100;assert(ObPublish(&c,&b,1600,&n)==OB_OK&&n==3);assert(ObRead(&c,0,tag,1600,&r)==OB_OK&&r.RateKnown&&r.RateMa==100);Cases++;
 b=Batch(9,1800);b.RateKnown[0]=1;b.Words[0][8]=101;assert(ObPublish(&c,&b,1800,&n)==OB_OK&&n==1);Cases++;
 b=Batch(10,2000);assert(ObPublish(&c,&b,2000,&n)==OB_OK&&n==1);Cases++;
 assert(ObRead(&c,0,tag,2000+OB_MAX_AGE_US,&r)==OB_OK);assert(ObTick(&c,2000+OB_MAX_AGE_US+1,&n)==OB_NO_DEVICE&&n==3);assert(ObTick(&c,2000+OB_MAX_AGE_US+2,&n)==OB_NO_DEVICE&&!n);old=tag;Cases++;
 b=Batch(11,2000+OB_MAX_AGE_US+3);Publish(&c,&b);assert(c.LastTag!=old&&ObRead(&c,0,old,b.EndUs,&r)==OB_NO_DEVICE);tag=c.LastTag;Cases++;
 assert(ObRead(&c,0,tag,b.EndUs-1,&r)==OB_NO_DEVICE&&!c.Present);assert(ObTick(&c,b.EndUs,&n)==OB_NO_DEVICE&&n==3);Cases++;
 Begin(&c);b=Batch(1,200);Publish(&c,&b);assert(ObBeginOwner(&c,2,&n)==OB_OK&&n==3&&!c.Present);b.OwnerEpoch=2;b.Sequence=1;b.BeginUs=300;b.EndUs=400;Publish(&c,&b);tag=c.LastTag;
 b.OwnerEpoch=1;b.Sequence=99;assert(ObPublish(&c,&b,400,&n)==OB_OLD_OWNER&&c.Present&&c.LastTag==tag);Cases++;
 b.OwnerEpoch=2;b.Sequence=1;assert(ObPublish(&c,&b,400,&n)==OB_OLD_INPUT&&c.Present);Cases++;
 for(unsigned mode=0;mode<25;mode++){
  Begin(&c);b=Batch(1,200);Publish(&c,&b);b=Batch(2,400);
  switch(mode){
   case 0:b.OwnerQualified=0;break;case 1:b.Complete=0;break;case 2:b.BeginUs=0;break;case 3:b.BeginUs=b.EndUs+1;break;
   case 4:b.BeginUs=1;b.EndUs=OB_MAX_BATCH_US+2;break;case 5:b.Words[0][0]^=1;break;case 6:b.Words[1][1]^=1;break;case 7:b.Words[0][2]^=1;break;
   case 8:b.Words[1][3]=1999;break;case 9:b.Words[0][3]=4001;break;case 10:b.Words[0][4]=999;break;case 11:b.Words[1][4]=6001;break;
   case 12:b.Words[0][7]=0;break;case 13:b.Words[1][6]=1001;break;case 14:b.Words[0][9]=101;break;case 15:b.Words[1][5]=65536;break;
   case 16:b.PowerKnown[0]=2;break;case 17:b.PowerState[0]=16;break;case 18:b.PowerKnown[0]=0;break;
   case 19:b.PowerState[0]=OB_CHARGING|OB_DISCHARGING;break;case 20:b.RateKnown[1]=2;break;
   case 21:b.RateKnown[0]=1;b.Words[0][8]=0xffff;break;case 22:b.PowerState[0]=OB_DISCHARGING;b.RateKnown[0]=1;b.Words[0][8]=1;break;
   case 23:b.PowerState[0]=OB_ONLINE;b.PowerState[1]=OB_DISCHARGING;break;case 24:b.PowerState[0]=OB_ONLINE;b.PowerKnown[1]=b.PowerState[1]=0;break;
  }
  assert(ObPublish(&c,&b,b.EndUs,&n)==OB_INVALID_DATA&&!c.Present&&n==3);assert(ObPublish(&c,&b,b.EndUs,&n)==OB_OLD_INPUT);Cases++;
 }
 Begin(&c);b=Batch(1,200);assert(ObPublish(&c,&b,199,&n)==OB_INVALID_DATA);b.Sequence=2;assert(ObPublish(&c,&b,200+OB_MAX_AGE_US+1,&n)==OB_INVALID_DATA);Cases++;
 Begin(&c);b=Batch(1,200);c.LastTag=UINT32_MAX;assert(ObPublish(&c,&b,200,&n)==OB_EXHAUSTED&&c.Exhausted&&!c.Present);assert(ObBeginOwner(&c,2,&n)==OB_EXHAUSTED);Cases++;
 Begin(&c);b=Batch(1,200);Publish(&c,&b);tag=c.LastTag;assert(ObRead(&c,2,tag,200,&r)==OB_ARGUMENT);assert(ObRead(&c,0,0,200,&r)==OB_NO_DEVICE);assert(ObSetNotify(&c,0,tag,200,0,2,1,&n)==OB_ARGUMENT);Cases++;
 printf("{\"passed\":true,\"behavior_checks\":%u,\"native_fixture_words_replayed\":true,\"resource_lease_power_and_time_explicitly_modeled\":true,\"native_operations\":0}\n",Cases);return 0;
}
