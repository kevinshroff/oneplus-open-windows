/* SPDX-License-Identifier: MIT
 * Undo only the separately captured completed G41 transaction. Never start SPI
 * or enable a supply. Original failed G41 evidence is not modified.
 */
#include "g43_recovery.h"
#include "g43_recovery_binding.h"
static void Copy(uint32_t*to,const uint32_t*from,unsigned count)
{
 unsigned i;for(i=0;i<count;i++)to[i]=from[i];
}
void G43RecoverHeld(const G43_POWER_IO*power,const G43_TOUCH_IO*touch,G43_TRIAL_RESULT*r)
{
 G43_SPI_IO spi={power->Rsc.Context,power->Rsc.Read,power->Rsc.Write,power->Observer.WaitMicrosecond,0};
 G43_ENGINE_IO engine={power->Rsc.Context,power->Rsc.Read,power->Rsc.Write,power->Observer.WaitMicrosecond,0};
 unsigned i;static const uint8_t on[8]={8,7,8,7,7,7,128,0};
 r->Power.Stage=1;r->Power.SourceStatusBaseline=0x43;
 r->Power.ClientBefore[0]=1800;r->Power.ClientBefore[1]=7;r->Power.ClientBefore[2]=0x80000000;
 r->Power.ClientOn=G43HeldValues[12];
 Copy(r->Touch.BeforePins,G43OriginalTouchPins,12);Copy(r->Touch.LengthsBefore,G43OriginalLengths,2);
 Copy(r->Spi.BeforeClock,G43OriginalClock,6);Copy(r->Spi.BeforePins,G43OriginalSpiPins,16);
 r->Spi.DirtyPins=15;r->Spi.VoteDirty=1;r->Spi.VoteEnabled=G43HeldClock[0];
 Copy(r->Spi.Engine.Before,G43OriginalEngine,24);Copy(r->Spi.Engine.DfsBefore,G43OriginalDfs,25);
 r->Spi.Engine.Dirty=G43_RECOVERY_ENGINE_DIRTY;r->Spi.Engine.Index=G43_RECOVERY_INDEX;
 r->Spi.Engine.SourceHz=19200000;r->Spi.Engine.BusHz=960000;
 G43Observe(&power->Observer,&r->Touch.PoweredPmic);
 if(r->Touch.PoweredPmic.Code){r->Power.Code=101;r->Power.ObserverUncertain=1;return;}
 if(r->Touch.PoweredPmic.Status!=0xc7){r->Power.Code=102;return;}
 for(i=0;i<8;i++)if(r->Touch.PoweredPmic.Configuration[i]!=on[i]){r->Power.Code=102;return;}
 r->Power.OnVerified=1;
 if(!G43CheckSpiHeld(&spi,&r->Spi,G43HeldClock,G43HeldSpiPins)){r->Power.Code=103;return;}
 if(!G43CheckEngineHeld(&engine,&r->Spi.Engine,G43HeldEngine)){r->Power.Code=104;return;}
 if(!G43RestoreTouchHeld(touch,&r->Touch,G43HeldTouchPins)){r->Power.Code=105;return;}
 if(!G43RestoreEngineHeld(&engine,&r->Spi.Engine)){r->Power.Code=106;return;}
 if(!G43RestoreSpiHeld(&spi,&r->Spi)){r->Power.Code=107;return;}
 r->SafeRelease=1;
 G43ReleaseHeld(power,&r->Power);
 /* Independently observed applied writes can be safe while retaining a
  * callback warning. Preserve it instead of disguising it as clean success. */
 if((r->Touch.Code||r->Spi.Code||r->Spi.Engine.Code)&&!r->Power.Code)r->Power.Code=108;
}
