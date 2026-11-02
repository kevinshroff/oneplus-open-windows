/* SPDX-License-Identifier: MIT */
#include "g58_input.h"
static int Same(const uint8_t*a,const uint8_t*b,uint32_t n){uint32_t i;for(i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
int G58InputStage(G58_INPUT*s,const uint8_t*raw,uint32_t n,uint16_t scan)
{
 uint32_t i;G58_FRAME frame;if(!s)return 0;
 if(s->Error||s->PendingValid||s->StopAttempts||!raw||n<8||n>G58_REPORT_MAX){s->Error=1;return 0;}
 G58DecodeReport(raw,n,&frame);
 if(frame.Kind!=G58_FRAME_CONTACTS||!G58HIDPrepare(&s->Accepted,raw,n,scan,&s->Pending)){s->Error=2;return 0;}
 for(i=0;i<n;i++)s->Raw[i]=raw[i];s->RawBytes=n;s->Scan=scan;s->PendingValid=1;s->Staged++;return 1;
}
int G58InputPublish(G58_INPUT*s,const G58_INPUT_IO*io,const uint8_t*raw,uint32_t n)
{
 G58HID_PLAN proof;if(!s||!io||!io->Submit)return 0;
 if(s->Error||!s->PendingValid||s->StopAttempts||!raw||n!=s->RawBytes||!Same(raw,s->Raw,n)){s->Error=3;return 0;}
 /* Reconstruct from accepted state and exact raw bytes; a staged flag or
  * cached coordinates never authorize a different or stale submission. */
 if(!G58HIDPrepare(&s->Accepted,raw,n,s->Scan,&proof)||proof.HaveReport!=s->Pending.HaveReport||proof.FromGeneration!=s->Pending.FromGeneration||!Same(proof.Report,s->Pending.Report,64)){s->Error=4;return 0;}
 s->PendingValid=0;s->Published++;
 if(!proof.HaveReport){s->NoReport++;return 1;}
 s->SubmitAttempts++;
 if(!io->Submit(io->Context,proof.Report)){s->Error=5;return 0;}
 s->SubmitAccepted++;
 if(!G58HIDCommit(&s->Accepted,&proof)){s->Error=6;return 0;}
 return 1;
}
int G58InputStop(G58_INPUT*s,const G58_INPUT_IO*io,uint16_t scan)
{
 G58HID_PLAN release;if(!s||!io||!io->Submit)return 0;
 if(s->StopAttempts)return s->Accepted.Mask==0;
 s->StopAttempts=1;s->PendingValid=0;
 if(!G58HIDReleaseAll(&s->Accepted,scan,&release)){s->Error=7;return 0;}
 if(!release.HaveReport)return 1;
 s->SubmitAttempts++;
 if(!io->Submit(io->Context,release.Report)){s->Error=8;return 0;}
 s->SubmitAccepted++;s->StopAccepted=1;
 if(!G58HIDCommit(&s->Accepted,&release)){s->Error=9;return 0;}
 return 1;
}
