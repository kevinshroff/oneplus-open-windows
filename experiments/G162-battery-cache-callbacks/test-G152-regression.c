/* Controlled owner/power semantics; demonstrates two old notification defects. */
#include "battery_cache.h"
#include <assert.h>
#include <stdio.h>
int main(void){
 OB_CACHE c;OB_BATCH b={0};uint32_t n=0;ObInitialize(&c);assert(ObBeginOwner(&c,1,&n)==OB_OK);
 b.OwnerEpoch=b.Sequence=b.OwnerQualified=b.Complete=1;b.BeginUs=100;b.EndUs=200;
 for(unsigned i=0;i<2;i++){uint32_t w[10]={0x6002,0x602,0x200,3000,3800,0x181,500,1000,0,50};for(unsigned j=0;j<10;j++)b.Words[i][j]=w[j];b.PowerKnown[i]=1;b.PowerState[i]=OB_CHARGING;}
 assert(ObPublish(&c,&b,200,&n)==OB_OK&&n==3);b.Sequence++;b.BeginUs=300;b.EndUs=400;b.PowerState[0]=b.PowerState[1]=0;
 assert(ObPublish(&c,&b,400,&n)==OB_OK);unsigned missing=(n==0);
 assert(ObSetNotify(&c,0,c.LastTag,400,OB_CHARGING,0,1000,&n)==OB_OK);unsigned clearedNotDetected=(n==0);
 assert(missing&&clearedNotDetected);
 printf("{\"reproduced\":true,\"missing_mandatory_stop_charging_notification\":true,\"cleared_power_bit_not_detected_by_requested_notification\":true,\"owner_power_and_time_modeled\":true,\"native_operations\":0}\n");return 0;
}
