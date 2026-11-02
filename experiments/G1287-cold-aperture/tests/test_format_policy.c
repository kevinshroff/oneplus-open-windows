#include "fault_policy.h"
#include <assert.h>
#include <stdio.h>
int main(void){unsigned n=0;for(unsigned context=1;context<=2;context++){
 OF_JOURNAL j={0};assert(!OfAckPolicy(&j,context,0x400)&&!j.Fatal&&!j.Events&&!j.AckWrites&&j.LastStatus[context]==0x400);n++;
 assert(!OfAckPolicy(&j,context,0)&&!j.Fatal);n++;
 for(unsigned bit=0;bit<32;bit++){if(bit==10)continue;OF_JOURNAL a={0};unsigned v=0x400u|(1u<<bit);unsigned ack=OfAckPolicy(&a,context,v);assert(a.Fatal&&a.Events==1&&a.LastStatus[context]==v);assert(ack==(v&0x800001feu));assert(!(ack&0x40000600u));n++;}
 OF_JOURNAL a={0};assert(!OfAckPolicy(&a,context,0xffffffff)&&a.Fatal&&a.InvalidReads==1&&!a.AckWrites);n++;
 }
 OF_JOURNAL g={0};assert(OfAckPolicy(&g,0,0x400)==0x400&&g.Fatal&&g.Events==1);n++;
 printf("PASS %u Format/context/global/fault/unknown/SS/allones policy cases; no Format W1C\n",n);return 0;}
