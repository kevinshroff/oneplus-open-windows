/* Reuse the existing actual-ISR shim; add the complete stalled TF combination. */
#include "g1341_cb0_policy.h"
#define main g1339_existing_cases
#include "test_isr.c"
#undef main
int main(void){
 int rc=g1339_existing_cases();assert(rc==0);
 _Static_assert((OGO_GPU_CB0_SCTLR^0x00c00067u)==(OGO_GPU_CB0_STALL_ON_FAULT?0x180u:0u),"only CFCFG/HUPCF change");
 fresh();assert(call(2,0x40000402u));
 assert(f.Journal.Fatal==1&&f.Journal.AckWrites==1);
 assert(maps[2][0x58/4]==0x40000400u); /* SS and Format are not acknowledged. */
 assert(f.Journal.First.Status==0x40000402u&&f.Journal.First.State==2);
 unsigned writes=0;
 for(unsigned i=0;i<count;i++)if(trace[i].Kind=='W'){
  assert(trace[i].Region==2&&trace[i].Offset==0x58&&trace[i].Value==2);writes++;
 }
 assert(writes==1&&logs==1); /* No RESUME or retry write exists. */
 assert(trace[8].Kind=='L'&&trace[9].Kind=='W');
 puts("PASS G1341 stalled TF retained, tuple before ACK, no SS ACK or RESUME");return 0;
}
