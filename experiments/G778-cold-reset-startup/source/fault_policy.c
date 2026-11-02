#include "fault_policy.h"
OF_WORD OfAckPolicy(OF_JOURNAL*j,OF_WORD index,OF_WORD observed){
 if(!j||index>1)return 0;j->LastStatus[index]=observed;if(!observed)return 0;
 if(j->Events<0x7fffffff)j->Events++;j->Fatal=1;if(observed==OF_ALLONES){if(j->InvalidReads<OF_ALLONES)j->InvalidReads++;return 0;}
 if(j->AckWrites<OF_ALLONES)j->AckWrites++;return observed; /* source W1C exactly observed, no RESUME */
}
