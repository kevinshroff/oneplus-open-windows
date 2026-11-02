#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "resources.h"
static OP182_RESOURCE Raw[OP182_RESOURCE_COUNT],Translated[OP182_RESOURCE_COUNT];
static unsigned Cases;
static void Reset(void){memcpy(Raw,OP182Expected,sizeof(Raw));memcpy(Translated,OP182Expected,sizeof(Translated));for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++)Raw[i].Share=Translated[i].Share=1;}
static void Check(int good){assert((Op182Validate(Raw,Translated,OP182_RESOURCE_COUNT)==0)==good);Cases++;}
int main(void){
 Reset();Check(1);
 for(unsigned rotation=1;rotation<OP182_RESOURCE_COUNT;rotation++){Reset();for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){Raw[i]=OP182Expected[(i+rotation)%OP182_RESOURCE_COUNT];Raw[i].Share=1;Translated[i]=Raw[i];}Check(1);}
 for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){
  Reset();Raw[i].Share=Translated[i].Share=3;Check(!OP182Expected[i].Write);
  Reset();Raw[i].Share=Translated[i].Share=0;Check(0);
  Reset();Raw[i].Share=Translated[i].Share=4;Check(0);
  Reset();Raw[i].Base=Translated[i].Base=UINT64_MAX;Check(0);
  Reset();Raw[i].Bytes=Translated[i].Bytes=OP182Expected[i].Bytes-1;Check(0);
  Reset();Raw[i].Write=Translated[i].Write=!Raw[i].Write;Check(0);
  Reset();Raw[i].Base+=4096;Check(0);
  Reset();Raw[i]=Raw[(i+1)%OP182_RESOURCE_COUNT];Translated[i]=Raw[i];Check(0);
 }
 Reset();assert(Op182Validate(NULL,Translated,20)&&Op182Validate(Raw,NULL,20)&&Op182Validate(Raw,Translated,19)&&Op182Validate(Raw,Translated,21));Cases+=4;
 printf("{\"passed\":true,\"actual_resource_validator_cases\":%u,\"native_operations\":0}\n",Cases);return 0;
}
