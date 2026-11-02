/* SPDX-License-Identifier: MIT
 * One cold digital-supply acquire/release. AVDD off, reset asserted and no
 * SPI/clock/GPIO operation. Preserve the first failure, every callback trace,
 * and the exact starting raw0 rather than normalizing it for an old caller.
 */
#include "g89_power.h"
static const uint32_t Pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};
static const uint32_t PinValues[8]={1,0,0x201,0,1,0,0xe2,0};
static void Error(G89_POWER_RESULT*r,uint32_t code){if(!r->Code)r->Code=code;}
static void UndoError(G89_POWER_RESULT*r,uint32_t code){if(!r->RestoreError)r->RestoreError=code;}
static int Valid(const G89_POWER_IO*io)
{return io&&io->Rsc.Read&&io->Rsc.Write&&io->Rsc.WaitMillisecond&&io->Observer.Read&&io->Observer.Write&&io->Observer.WaitMicrosecond&&io->WaitTenMilliseconds;}
static int Guards(const G89_POWER_IO*io,uint32_t*out)
{for(unsigned i=0;i<8;i++)if(!io->Rsc.Read(io->Rsc.Context,Pins[i],out+i)||out[i]!=PinValues[i])return 0;return 1;}
static int PmicState(const G89_OBS_RESULT*p,int on)
{
 const uint8_t off[8]={8,7,0,0,7,7,0,0},active[8]={8,7,8,7,7,7,128,0};const uint8_t*cfg=on?active:off;
 if(p->Code||p->Status!=(on?0xc7u:0x43u))return 0;for(unsigned i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int Observe(const G89_POWER_IO*io,G89_POWER_RESULT*r,unsigned kind)
{
 if(r->PmicCount>=3||r->ObserverUncertain){Error(r,10);return 0;}
 unsigned i=r->PmicCount++;r->PmicKinds[i]=kind;G89Observe(&io->Observer,r->Pmic+i);
 if(r->Pmic[i].Code){r->ObserverUncertain=1;Error(r,11+kind);return 0;}
 if(!PmicState(r->Pmic+i,kind==1)){Error(r,14+kind);return 0;}
 if(kind!=1){r->OffVerified=1;r->LastOffObserveTxn=r->TxnCount;}return 1;
}
typedef struct{const G89_RSC_IO*Original;G89_POWER_RESULT*Result;}TransferContext;
static int TransferRead(void*p,uint32_t at,uint32_t*v){TransferContext*c=p;return c->Original->Read(c->Original->Context,at,v);}
static int TransferWrite(void*p,uint32_t at,uint32_t v){TransferContext*c=p;return c->Original->Write(c->Original->Context,at,v);}
static void TransferWait(void*p){TransferContext*c=p;c->Result->Waits1ms++;c->Original->WaitMillisecond(c->Original->Context);}
static G89_RSC_RESULT*Transaction(const G89_POWER_IO*io,G89_POWER_RESULT*r,uint32_t addr,int mode)
{
 if(r->TxnCount>=G89_TXNS||r->RscUncertain){Error(r,90);return 0;}
 if(mode!=G89_READ&&!(mode==G89_ON_ACK&&r->PreflightVerified&&!r->EnableAttempted&&!r->ReleaseStarted)&&!(mode==G89_OFF_NO_ACK&&r->EnableAttempted&&r->ReleaseStarted&&!r->ReleaseAttempted)){Error(r,91);return 0;}
 unsigned i=r->TxnCount++;G89_RSC_RESULT*t=r->Transactions+i;TransferContext c={&io->Rsc,r};G89_RSC_IO transport={&c,TransferRead,TransferWrite,TransferWait};G89Transfer(&transport,t,addr,mode==G89_ON_ACK?1:0,mode);
 if(i==0&&t->Mutated){r->History=t->Before[12];r->HistoryValid=r->History==0||r->History==7;}
 if(mode==G89_ON_ACK&&t->Triggered){r->EnableAttempted=1;r->EnableTxn=i+1;r->NeedsRelease=1;r->OffVerified=0;}
 if(mode==G89_OFF_NO_ACK&&t->Triggered){r->ReleaseAttempted=1;r->ReleaseTxn=i+1;r->OffVerified=0;}
 if(!t->Restored)r->RscUncertain=1;
 if(t->Code||!t->Restored)Error(r,20+i+1);return t;
}
static int Query(const G89_POWER_IO*io,G89_POWER_RESULT*r,uint32_t addr,uint32_t*out)
{G89_RSC_RESULT*t=Transaction(io,r,addr,G89_READ);if(!t||t->Code||!t->Restored)return 0;*out=t->Response;return 1;}
static void Settle(const G89_POWER_IO*io,G89_POWER_RESULT*r)
{r->Waits10ms++;io->WaitTenMilliseconds(io->Rsc.Context);}
static void Finish(const G89_POWER_IO*io,G89_POWER_RESULT*r)
{
 if(!Guards(io,r->GuardAfter)){UndoError(r,7);return;}
 if(r->RscUncertain||r->ObserverUncertain||r->RestoreError||!r->OffVerified)return;
 for(unsigned i=0;i<r->TxnCount;i++)if(!r->Transactions[i].Restored)return;
 if(r->TxnCount&&(!r->HistoryValid||r->Transactions[r->TxnCount-1].After[12]!=r->History)){UndoError(r,8);return;}
 if(r->EnableAttempted){
  if(!r->ReleaseStarted||r->LastOffObserveTxn<r->EnableTxn||r->LastOffObserveTxn<r->ReleaseTxn)return;
  if(r->ClientAfter[0]!=1800||r->ClientAfter[1]!=7||r->ClientAfter[2]!=0)return;
 }
 r->Restored=1;r->NeedsRelease=0;r->Active=0;if(!r->Code&&r->OnVerified&&r->ReleaseStarted)r->Stage=0;
}
int G89SupplyAcquire(const G89_POWER_IO*io,G89_POWER_RESULT*r)
{
 G89_RSC_RESULT*t;if(!r)return 0;
 if(r->Started||r->Code||r->RestoreError||r->TxnCount||r->PmicCount||r->Active||r->NeedsRelease)return 0;
 if(!Valid(io)){Error(r,99);return 0;}r->Started=1;r->Stage=1;
 if(!Guards(io,r->GuardBefore)){Error(r,1);goto done;}
 if(!Observe(io,r,0))goto done;r->Stage=2;
 if(!Query(io,r,0x40800,r->ClientBefore)||!r->HistoryValid){Error(r,2);goto done;}
 if(!Query(io,r,0x40808,r->ClientBefore+1)||!Query(io,r,0x40804,r->ClientBefore+2))goto done;
 if(r->ClientBefore[0]!=1800||r->ClientBefore[1]!=7||r->ClientBefore[2]!=0){Error(r,3);goto done;}
 r->PreflightVerified=1;r->Stage=3;t=Transaction(io,r,0x40804,G89_ON_ACK);
 if(!t||t->Code||!t->Restored)goto done;
 if(!Query(io,r,0x40804,&r->ClientOn))goto done;
 if(r->ClientOn!=0x80000001u){Error(r,4);goto done;}
 Settle(io,r);if(!Observe(io,r,1))goto done;
 if(!Guards(io,r->GuardOn)){Error(r,5);goto done;}
 r->OnVerified=1;r->Active=1;r->AcquireFinished=1;r->Stage=4;return 1;
 done:if(!r->EnableAttempted)Finish(io,r);return 0;
}
int G89SupplyRelease(const G89_POWER_IO*io,G89_POWER_RESULT*r)
{
 G89_RSC_RESULT*t;if(!r||!r->Started||!r->EnableAttempted||r->ReleaseStarted)return 0;
 if(!Valid(io)){Error(r,99);return 0;}r->ReleaseStarted=1;r->Stage=90;
 if(r->RscUncertain){UndoError(r,1);goto done;}
 if(!Guards(io,r->GuardRelease)){UndoError(r,2);goto done;}
 if(!Query(io,r,0x40800,r->ClientAtRelease)||!Query(io,r,0x40808,r->ClientAtRelease+1)||!Query(io,r,0x40804,r->ClientAtRelease+2)){UndoError(r,3);goto done;}
 if(r->ClientAtRelease[0]!=1800||r->ClientAtRelease[1]!=7||(r->ClientAtRelease[2]!=0&&r->ClientAtRelease[2]!=0x80000000u&&r->ClientAtRelease[2]!=0x80000001u)){UndoError(r,4);goto done;}
 if(r->ClientAtRelease[2]!=0){
  t=Transaction(io,r,0x40804,G89_OFF_NO_ACK);if(!t||!t->Restored){UndoError(r,5);goto done;}
  /* An owned, reclaimed failed callback is never repeated. Readback and
   * independent PMIC-off may prove cleanup while preserving its error. */
 }
 if(!Query(io,r,0x40800,r->ClientAfter)){UndoError(r,6);goto done;}
 if(r->History==0){
  if(!Query(io,r,0x40808,r->ClientAfter+1)||!Query(io,r,0x40804,r->ClientAfter+2)){UndoError(r,6);goto done;}
 }else{
  if(!Query(io,r,0x40804,r->ClientAfter+2)||!Query(io,r,0x40808,r->ClientAfter+1)){UndoError(r,6);goto done;}
 }
 if(r->ClientAfter[0]!=1800||r->ClientAfter[1]!=7||r->ClientAfter[2]!=0){UndoError(r,6);goto done;}
 Settle(io,r);if(!Observe(io,r,2)){UndoError(r,9);goto done;}
 done:Finish(io,r);return r->Restored==1;
}
void G89PowerTrial(const G89_POWER_IO*io,G89_POWER_RESULT*r)
{if(!r||r->Started)return;G89SupplyAcquire(io,r);if(Valid(io)&&r->EnableAttempted&&!r->ReleaseStarted)G89SupplyRelease(io,r);}
