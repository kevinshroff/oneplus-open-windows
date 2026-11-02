/* SPDX-License-Identifier: MIT
 * One LDO4 digital-supply enable/release trial. AVDD remains off/reset asserted.
 * Keeps full raw telemetry; only the historical status43 -> c7 ->43 is accepted.
 */
#include "g46_power.h"
static const uint8_t Off[8]={8,7,0,0,7,7,0,0},On[8]={8,7,8,7,7,7,128,0};
static const uint32_t Pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};
static const uint32_t PinValues[8]={1,0,0x201,0,1,0,0xe2,0};
static int Guards(const G46_POWER_IO*io,uint32_t*out)
{
 unsigned i;for(i=0;i<8;i++)if(!io->Rsc.Read(io->Rsc.Context,Pins[i],&out[i])||out[i]!=PinValues[i])return 0;return 1;
}
static int Observe(const G46_POWER_IO*io,G46_POWER_RESULT*r,unsigned index)
{
 if(index>=3||r->ObserverUncertain)return 0;
 r->PmicCount=index+1;G46Observe(&io->Observer,&r->Pmic[index]);
 if(r->Pmic[index].Code){r->ObserverUncertain=1;if(!r->Code)r->Code=10+index;return 0;}return 1;
}
static int PmicState(const G46_OBS_RESULT*p,int on)
{
 unsigned i;const uint8_t*cfg=on?On:Off;
 for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;
 return p->Status==(on?0xc7u:0x43u);
}
static int Transfer(const G46_POWER_IO*io,G46_POWER_RESULT*r,uint32_t at,uint32_t data,int writing,uint32_t*out)
{
 G46_RSC_RESULT*x;
 if(r->TxnCount>=9||r->RscUncertain){if(!r->Code)r->Code=30;return 0;}
 x=&r->Transactions[r->TxnCount++];G46Transfer(&io->Rsc,x,at,data,writing);
 if(writing&&data==1&&x->Triggered){r->EnableAttempted=1;r->OffVerified=0;}
 if(writing&&data==0&&x->Triggered)r->ReleaseAttempted=1;
 if(!x->Restored)r->RscUncertain=1;
 if(x->Code||!x->Restored){if(!r->Code)r->Code=30+r->TxnCount;return 0;}
 if(out)*out=x->Response;return 1;
}
static void Wait10(const G46_POWER_IO*io,G46_POWER_RESULT*r)
{
 r->Waits10ms++;io->WaitTenMilliseconds(io->Rsc.Context);
}
static int Release(const G46_POWER_IO*io,G46_POWER_RESULT*r)
{
 r->Stage=90;
 if(r->RscUncertain){r->RestoreError=1;return 0;}
 if(!Transfer(io,r,0x40804,0,1,0)){r->RestoreError=2;return 0;}
 if(!Transfer(io,r,0x40804,0,0,&r->ClientAfter[2])||
    !Transfer(io,r,0x40800,0,0,&r->ClientAfter[0])||
    !Transfer(io,r,0x40808,0,0,&r->ClientAfter[1])){r->RestoreError=3;return 0;}
 if(r->ClientAfter[0]!=r->ClientBefore[0]||r->ClientAfter[1]!=r->ClientBefore[1]||
    r->ClientAfter[2]!=r->ClientBefore[2]){r->RestoreError=4;return 0;}
 Wait10(io,r);
 if(!Observe(io,r,2)||!PmicState(&r->Pmic[2],0)){r->RestoreError=5;return 0;}
 r->OffVerified=1;return 1;
}
void G46PowerTrial(const G46_POWER_IO*io,G46_POWER_RESULT*r)
{
 unsigned i;r->Stage=1;r->SourceStatusBaseline=0x43;
 if(!Guards(io,r->GuardBefore)){r->Code=1;return;}
 if(!Observe(io,r,0)||!PmicState(&r->Pmic[0],0)){if(!r->Code)r->Code=2;return;}
 r->OffVerified=1;r->Stage=2;
 if(!Transfer(io,r,0x40800,0,0,&r->ClientBefore[0])||
    !Transfer(io,r,0x40808,0,0,&r->ClientBefore[1])||
    !Transfer(io,r,0x40804,0,0,&r->ClientBefore[2]))goto done;
 /* G40 observed cold-boot raw-enable0 ->80000001 ->80000000. Until
  * bit31 semantics are established, admit only the complete previously
  * qualified raw profile, before sending any enable write. */
 if(r->ClientBefore[0]!=1800||r->ClientBefore[1]!=7||r->ClientBefore[2]!=0x80000000u){r->Code=3;goto done;}
 r->PreflightVerified=1;r->Stage=3;
 if(!Transfer(io,r,0x40804,1,1,0))goto done;
 if(!Transfer(io,r,0x40804,0,0,&r->ClientOn))goto done;
 if(r->ClientOn!=(r->ClientBefore[2]|1u)){r->Code=4;goto done;}
 Wait10(io,r);
 if(!Observe(io,r,1)||!PmicState(&r->Pmic[1],1)){if(!r->Code)r->Code=5;goto done;}
 r->OnVerified=1;
 if(io->Powered&&!io->Powered(io->Rsc.Context)&&!r->Code)r->Code=6;
 done:
 if(r->EnableAttempted&&!r->ReleaseAttempted){
  if(io->SafeToRelease&&!io->SafeToRelease(io->Rsc.Context)){r->RestoreError=7;return;}
  Release(io,r);
 }
 if(!Guards(io,r->GuardAfter)){if(!r->RestoreError)r->RestoreError=6;return;}
 for(i=0;i<r->TxnCount;i++)if(r->Transactions[i].Mutated&&!r->Transactions[i].Restored)return;
 if(r->OffVerified&&!r->RscUncertain&&!r->ObserverUncertain&&!r->RestoreError)r->Restored=1;
 if(r->Code==0&&r->Restored&&r->OnVerified)r->Stage=0;
}
