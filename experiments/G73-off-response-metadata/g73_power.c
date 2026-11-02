/* SPDX-License-Identifier: MIT
 * The only resource writes in this experiment are OFF data0 at40804.
 * Test response-request metadata independently of supply enable. Never admit
 * unknown initial fields or call any GPIO/reset/SPI/clock operation.
 */
#include "g73_power.h"
static const uint32_t Pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};
static const uint32_t PinValues[8]={1,0,0x201,0,1,0,0xe2,0};
static int Guards(const G73_OFF_IO*io,uint32_t*out)
{for(unsigned i=0;i<8;i++)if(!io->Rsc.Read(io->Rsc.Context,Pins[i],out+i)||out[i]!=PinValues[i])return 0;return 1;}
static int Off(const G73_OBS_RESULT*p)
{static const uint8_t c[8]={8,7,0,0,7,7,0,0};if(p->Code||p->Status!=0x43)return 0;for(unsigned i=0;i<8;i++)if(p->Configuration[i]!=c[i])return 0;return 1;}
static int Observe(const G73_OFF_IO*io,G73_OFF_RESULT*r)
{
 if(r->PmicCount>=3||r->ObserverUncertain)return 0;
 G73_OBS_RESULT*p=&r->Pmic[r->PmicCount++];G73Observe(&io->Observer,p);
 if(p->Code){r->ObserverUncertain=1;if(!r->Code)r->Code=10;return 0;}
 if(!Off(p)){if(!r->Code)r->Code=11;return 0;}r->LastOffObserveTxn=r->TxnCount;return 1;
}
typedef struct{const G73_RSC_IO*Original;G73_OFF_RESULT*Result;}G73_TRANSFER_CONTEXT;
static int TransferRead(void*p,uint32_t at,uint32_t*v){G73_TRANSFER_CONTEXT*c=p;return c->Original->Read(c->Original->Context,at,v);}
static int TransferWrite(void*p,uint32_t at,uint32_t v){G73_TRANSFER_CONTEXT*c=p;return c->Original->Write(c->Original->Context,at,v);}
static void TransferWait(void*p){G73_TRANSFER_CONTEXT*c=p;c->Result->Waits1ms++;c->Original->WaitMillisecond(c->Original->Context);}
static G73_RSC_RESULT*Transaction(const G73_OFF_IO*io,G73_OFF_RESULT*r,uint32_t addr,int mode)
{
 if(r->TxnCount>=G73_TXNS||r->RscUncertain){if(!r->Code)r->Code=12;return 0;}
 G73_RSC_RESULT*t=&r->Transactions[r->TxnCount++];G73_TRANSFER_CONTEXT context={&io->Rsc,r};G73_RSC_IO transport={&context,TransferRead,TransferWrite,TransferWait};G73Transfer(&transport,t,addr,0,mode);
 if(mode!=G73_READ&&t->Triggered)r->LastOffWriteTxn=r->TxnCount;
 if(!t->Restored)r->RscUncertain=1;
 if((t->Code||!t->Restored)&&!r->Code)r->Code=20+r->TxnCount;
 return t;
}
static int Read(const G73_OFF_IO*io,G73_OFF_RESULT*r,uint32_t addr,uint32_t*value)
{
 G73_RSC_RESULT*t=Transaction(io,r,addr,G73_READ);
 if(!t||t->Code||!t->Restored)return 0;*value=t->Response;return 1;
}
void G73OffTrial(const G73_OFF_IO*io,G73_OFF_RESULT*r)
{
 G73_RSC_RESULT*t;uint32_t history=0;
 if(!r)return;
 if(!io||!io->Rsc.Read||!io->Rsc.Write||!io->Rsc.WaitMillisecond||!io->Observer.Read||!io->Observer.Write||!io->Observer.WaitMicrosecond){r->Code=99;return;}
 r->Stage=1;
 if(!Guards(io,r->GuardBefore)){r->Code=1;return;}
 if(!Observe(io,r))goto done;r->OffVerified=1;r->Stage=2;
 if(!Read(io,r,0x40800,&r->ClientBefore[0])||!Read(io,r,0x40808,&r->ClientBefore[1])||!Read(io,r,0x40804,&r->ClientBefore[2]))goto done;
 history=r->Transactions[0].Before[12];
 if((history!=0&&history!=7)||r->ClientBefore[0]!=1800||r->ClientBefore[1]!=7||r->ClientBefore[2]!=0){r->Code=2;goto done;}
 r->PreflightVerified=1;r->Stage=3;
 t=Transaction(io,r,0x40804,G73_OFF_ACK);if(!t)goto done;r->FlipAttempted=t->Triggered;
 if(r->RscUncertain)goto done;
 /* A failed write callback is not repeated. A completed, reclaimed transport
  * permits one readback; only the exact owned changed word allows restoration. */
 if(!Read(io,r,0x40804,&r->AckRaw))goto done;
 if(r->AckRaw==0){if(!r->Code)r->Code=3;r->OriginalVerified=1;goto verify_final;}
 if(r->AckRaw!=0x80000000u){if(!r->Code)r->Code=4;goto done;}
 if(!r->FlipAttempted){if(!r->Code)r->Code=6;goto done;}
 r->FlipVerified=1;r->Stage=4;
 if(!Observe(io,r))goto done;
 r->Stage=5;t=Transaction(io,r,0x40804,G73_OFF_NO_ACK);if(!t)goto done;r->RestoreAttempted=t->Triggered;
 if(r->RscUncertain)goto done;
 if(!Read(io,r,0x40804,&r->NoAckRaw))goto done;
 if(r->NoAckRaw!=0){r->RestoreError=1;if(!r->Code)r->Code=5;goto done;}
 r->OriginalVerified=1;
 verify_final:
 r->Stage=6;
 if(!Read(io,r,0x40800,&r->ClientAfter[0])||!Read(io,r,0x40808,&r->ClientAfter[1])||!Read(io,r,0x40804,&r->ClientAfter[2]))goto done;
 if(r->ClientAfter[0]!=1800||r->ClientAfter[1]!=7||r->ClientAfter[2]!=0){r->RestoreError=2;goto done;}
 if(history==7){uint32_t v;if(!Read(io,r,0x40808,&v)||v!=7)goto done;}
 if(!Observe(io,r))goto done;
 done:
 if(!Guards(io,r->GuardAfter)){if(!r->RestoreError)r->RestoreError=3;return;}
 if(r->RscUncertain||r->ObserverUncertain||r->RestoreError)return;
 for(unsigned i=0;i<r->TxnCount;i++)if(!r->Transactions[i].Restored)return;
 if(!r->OffVerified)return;
 /* Before any resource trigger, only query/controller metadata was touched.
  * After a trigger, exact raw vote and final independent off state are needed. */
 if(r->FlipAttempted||r->RestoreAttempted){
  if(!r->OriginalVerified||r->PmicCount<2||r->LastOffObserveTxn<r->LastOffWriteTxn||!Off(&r->Pmic[r->PmicCount-1]))return;
 }
 r->Restored=1;if(!r->Code&&r->FlipVerified&&r->RestoreAttempted&&r->OriginalVerified&&r->PmicCount==3)r->Stage=0;
}
