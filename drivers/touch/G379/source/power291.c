/* SPDX-License-Identifier: MIT */
#include "power291.h"
#include <string.h>
const uint8_t P291Descriptor[]={
 0x05,0x01,0x09,0x80,0xa1,0x01,0x85,0x01,
 0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x01,
 0x09,0x81,0x81,0x02,0x95,0x07,0x81,0x03,0xc0
};
const uint32_t P291DescriptorBytes=sizeof(P291Descriptor);
void P291Init(P291*p,uint64_t epoch,P291_SUBMIT submit,void*context)
{
 if(!p)return;
 memset(p,0,sizeof(*p));B192StreamInit(&p->Stream,epoch);
 p->Submit=submit;p->Context=context;
 if(!epoch||!submit)p->Fault=B192_ARGUMENT;
}
static int Send(P291*p,uint8_t down)
{
 uint8_t report[2]={1,down};
 p->DeliveryUncertain=1;
 if(!p->Submit(p->Context,report))return 0;
 p->AcceptedDown=down;p->DeliveryUncertain=0;return 1;
}
uint32_t P291Step(P291*p,uint64_t epoch,uint64_t sequence,const B192_SAMPLE*s)
{
 B192_STREAM *b;uint32_t observed,next;
 if(!p||!s)return B192_ARGUMENT;
 if(p->Fault)return p->Fault;if(p->Stopped)return B192_STOPPED;b=&p->Stream;
 if(!epoch||epoch!=b->Epoch||!sequence||b->LastSequence==UINT64_MAX||sequence!=b->LastSequence+1)
  return p->Fault=B192_SEQUENCE;
 if(b->Started&&s->AtUs<=b->LastUs)return p->Fault=B192_CLOCK;
 observed=(s->Raw[1]&0x80)?B192_POWER:0; /* HLOS bit7 only; volume bits ignored. */
 if(b->Started&&s->AtUs-b->LastUs>B192_MAX_GAP_US){
  /* Same hardware generation, no transaction retry or bus state reset. */
  if((p->AcceptedDown||p->DeliveryUncertain)&&!Send(p,0))return p->Fault=B192_RESULT;
  b->Stable=b->Candidate=0;p->Rearming=1;b->CandidateAt[0]=s->AtUs;p->GapRearms++;
 }
 if(!b->Started){if(observed)return p->Fault=B192_HELD_START;b->Started=1;b->CandidateAt[0]=s->AtUs;}
 if(p->Rearming){
  if(p->Rearming==2){b->CandidateAt[0]=s->AtUs;p->Rearming=1;}
  if(observed||b->Candidate!=observed)b->CandidateAt[0]=s->AtUs;
  else if(s->AtUs-b->CandidateAt[0]>=B192_DEBOUNCE_US)p->Rearming=0;
  b->Stable=0;b->Candidate=observed;
 }else{
  next=b->Stable;
  if(observed!=b->Candidate)b->CandidateAt[0]=s->AtUs;
  if(observed!=next&&s->AtUs-b->CandidateAt[0]>=B192_DEBOUNCE_US)next=observed;
  if(next!=b->Stable&&!Send(p,(uint8_t)next))return p->Fault=B192_RESULT;
  b->Stable=next;b->Candidate=observed;
 }
 b->LastSequence=sequence;b->LastUs=s->AtUs;return B192_OK;
}

int P291Suspend(P291*p)
{
 if(!p||p->Fault||p->Stopped)return 0;
 if((p->AcceptedDown||p->DeliveryUncertain)&&!Send(p,0)){
  p->Fault=B192_RESULT;return 0;
 }
 p->Stream.Stable=p->Stream.Candidate=0;p->Rearming=2;return 1;
}

int P291Stop(P291*p)
{
 B192_EVENT e;
 if(!p)return 0;
 if(p->Stopped)return !p->DeliveryUncertain&&!p->AcceptedDown;
 p->Stopped=1;B192StreamStop(&p->Stream,&e);
 if((p->AcceptedDown||p->DeliveryUncertain)&&p->Submit)return Send(p,0);
 return !p->DeliveryUncertain;
}
