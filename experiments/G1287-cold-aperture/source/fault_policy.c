#include "fault_policy.h"
/* Arm IHI0062D.c16.5.9: context FSR.Format[10:9] is generated read-only.
 * Our cold→AArch64 contexts permit Format0 or2; other format/unknown bits
 * remain fatal. SS is read-only; acknowledge only actual W1C fault bits. */
OF_WORD OfAckPolicy(OF_JOURNAL*j,OF_WORD index,OF_WORD observed){
 if(!j||index>2)return 0;j->LastStatus[index]=observed;
 if(!observed||(index&&observed==0x400u))return 0;
 if(j->Events<0x7fffffff)j->Events++;j->Fatal=1;
 if(observed==OF_ALLONES){if(j->InvalidReads<OF_ALLONES)j->InvalidReads++;return 0;}
 OF_WORD ack=index?(observed&0x800001feu):observed;
 if(ack&&j->AckWrites<OF_ALLONES)j->AckWrites++;return ack;
}
