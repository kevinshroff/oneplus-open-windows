/* SPDX-License-Identifier: MIT */
#include "g55_replay.h"
#include "g55_fixtures.h"
int G55Replay(G55_STATE*s,const G55_REPLAY_IO*io,G55_REPLAY_RESULT*r)
{
 uint32_t i;G55_PLAN p;
 if(!r)return 0;
 r->Attempted=r->Submitted=r->Accepted=r->CleanupAttempted=r->CleanupAccepted=r->Complete=r->Error=0;
 if(!s||!io||!io->Submit||!io->Wait25ms||!io->Scan100us||s->Mask||s->Generation){r->Error=4;return 0;}
 r->Attempted=1;
 for(i=0;i<4;i++){
  if(i&&!io->Wait25ms(io->Context)){r->Error=3;break;}
  if(!G55Prepare(s,G55ReplayRaw[i],26,io->Scan100us(io->Context),&p)||!p.HaveReport){r->Error=1;break;}
  r->Submitted++;
  if(!io->Submit(io->Context,p.Report)){r->Error=2;break;}
  r->Accepted++;
  if(!G55Commit(s,&p)){r->Error=5;break;}
 }
 if(i==4&&s->Mask==0){r->Complete=1;return 1;}
 /* Cleanup is a single UP constructed from last accepted IDs/positions.
  * A failed cleanup is retained as a failure and never retried here. */
 if(s->Mask&&G55ReleaseAll(s,io->Scan100us(io->Context),&p)&&p.HaveReport){
  r->CleanupAttempted=1;r->Submitted++;
  if(io->Submit(io->Context,p.Report)){
   r->CleanupAccepted=1;r->Accepted++;
   if(!G55Commit(s,&p))r->Error=5;
  }
 }
 return 0;
}
