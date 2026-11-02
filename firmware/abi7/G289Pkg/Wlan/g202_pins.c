/* SPDX-License-Identifier: MIT
 * Exact G200 chip_cfg@1 pin closure. ConfigGpio/GpioOut use the actual
 * TLMMDxe protocol, not guessed CPU writes. No interrupt/GIC programming.
 */
#include "g202_pins.h"
static const uint32_t Pins[4]={94,96,95,80};
static uint64_t Base(uint32_t I){return UINT64_C(0xf100000)+(uint64_t)Pins[I]*0x1000;}
uint32_t G202PinPacked(uint32_t G,uint32_t F,uint32_t D,uint32_t P,uint32_t S){
 return UINT32_C(0x20000000)|((G&0x3ffU)<<4)|(F&15U)|((D&1U)<<14)|((P&3U)<<15)|((S&15U)<<17);
}
static G202_STATUS Fail(G202_PINS*C,G202_STATUS E){if(!C->FirstError)C->FirstError=E;C->Uncertain=1;return E;}
static G202_STATUS Read(G202_PINS*C,uint64_t A,uint32_t*V){return C->Io.Read32(C->Io.Context,A,V);}
static G202_STATUS Words(G202_PINS*C,uint32_t I,G202_PIN_WORDS*W){
 G202_STATUS E=Read(C,Base(I),&W->Cfg);if(E)return E;
 E=Read(C,Base(I)+4,&W->InOut);if(E)return E;
 return Read(C,Base(I)+8,&W->IrqCfg);
}
G202_STATUS G202PinObserve(G202_PINS*C,G202_PIN_WORDS W[4],uint32_t*Selector){
 if(!C||!W||!Selector||!C->Io.Read32)return G202_ERR(2);
 G202_PIN_WORDS A[4];G202_STATUS E;
 for(uint32_t I=0;I<4;I++){E=Words(C,I,&A[I]);if(E)return E;}
 uint32_t S0,S1,C0,C1;
 E=Read(C,0xf153000,&C0);if(E)return E;E=Read(C,0xf153004,&S0);if(E)return E;
 for(uint32_t I=0;I<4;I++){
  E=Words(C,I,&W[I]);if(E)return E;
  /* Input values on WAKE/CLKREQ may change; config/output/IRQ must not. */
  uint32_t InOutMask=(I==0||I==3)?3U:2U;
  if(A[I].Cfg!=W[I].Cfg||((A[I].InOut^W[I].InOut)&InOutMask)||A[I].IrqCfg!=W[I].IrqCfg)return G202_ERR(6);
 }
 E=Read(C,0xf153000,&C1);if(E)return E;E=Read(C,0xf153004,&S1);if(E)return E;
 if(C0!=C1||((S0^S1)&1U)||(C1&0x123cU))return G202_ERR(6);
 *Selector=S1&1U;return 0;
}
static uint32_t ConfigWord(uint32_t F,uint32_t D,uint32_t P,uint32_t S){return P|(F<<2)|(S<<6)|(D<<9);}
static G202_STATUS Set(G202_PINS*C,uint32_t I,uint32_t F,uint32_t D,uint32_t P,uint32_t S,uint32_t Value){
 uint32_t Pack=G202PinPacked(Pins[I],F,D,P,S);G202_STATUS E;
 C->Touched|=1U<<I;
 /* Preload the output latch before enabling output, avoiding a high pulse. */
 if(D){E=C->Tlmm->GpioOut(Pack,Value);if(E)return Fail(C,E);}
 E=C->Tlmm->ConfigGpio(Pack,1);if(E)return Fail(C,E);
 G202_PIN_WORDS W;E=Words(C,I,&W);if(E)return Fail(C,E);
 if((W.Cfg&0x3ffU)!=ConfigWord(F,D,P,S)||((W.Cfg^C->Before[I].Cfg)&~0x3ffU)||
    W.IrqCfg!=C->Before[I].IrqCfg||(D&&((W.InOut>>1)&1U)!=Value))return Fail(C,G202_ERR(7));
 return 0;
}
G202_STATUS G202PinPrepare(G202_PINS*C){
 if(!C||C->Prepared||C->Touched||C->Uncertain||!C->Tlmm||C->Tlmm->Revision!=1||
    !C->Tlmm->ConfigGpio||!C->Tlmm->GpioOut||!C->Io.Read32||!C->Io.Stall)return G202_ERR(3);
 uint32_t Selector;G202_STATUS E=G202PinObserve(C,C->Before,&Selector);if(E)return E;
 /* Selected KIWI cold branch is still required before the first pin write.
  * GPIO83 is observed only; the source samples it before powering WLAN. */
 if(Selector!=0)return G202_ERR(6);
 for(uint32_t I=0;I<4;I++)if((C->Before[I].Cfg&0x1000U)||(C->Before[I].IrqCfg&1U))return G202_ERR(6);
 if((C->Before[0].Cfg&0x3cU)||(C->Before[3].Cfg&0x3cU)||
    ((C->Before[0].InOut|C->Before[3].InOut)&3U))return G202_ERR(6);
 E=Set(C,0,0,1,1,0,0);if(E)return E; /* PERST asserted first. */
 E=C->Io.Stall(C->Io.Context,1000);if(E)return Fail(C,E);
 E=Set(C,1,0,0,3,0,0);if(E)return E;
 /* Source assigns mux1/pullup/2mA; input direction is explicit pre-OS policy,
  * because the Linux pinctrl state itself does not specify direction. */
 E=Set(C,2,1,0,3,0,0);if(E)return E;
 E=Set(C,3,0,1,3,7,0);if(E)return E;
 C->Prepared=1;return 0;
}
G202_STATUS G202PinActivate(G202_PINS*C){
 if(!C||!C->Prepared||C->Uncertain||C->Active)return G202_ERR(6);
 G202_PIN_WORDS P;G202_STATUS E=Words(C,0,&P);if(E)return Fail(C,E);
 if((P.Cfg&0x3ffU)!=ConfigWord(0,1,1,0)||(P.InOut&3U))return Fail(C,G202_ERR(7));
 E=Set(C,3,0,1,3,7,1);if(E)return E;
 E=C->Io.Stall(C->Io.Context,1000);if(E)return Fail(C,E);
 C->Active=1;return 0;
}
G202_STATUS G202PinDeactivate(G202_PINS*C){
 if(!C||!C->Prepared||C->Uncertain)return G202_ERR(6);
 G202_STATUS E=Set(C,0,0,1,1,0,0);if(E)return E;
 E=Set(C,3,0,1,3,7,0);if(E)return E;
 E=C->Io.Stall(C->Io.Context,1000);if(E)return Fail(C,E);
 C->Active=0;return 0;
}
G202_STATUS G202PinRestore(G202_PINS*C){
 if(!C||!C->Prepared||C->Active||C->Uncertain)return G202_ERR(6);
 G202_PIN_WORDS W;G202_STATUS E=Words(C,0,&W);if(E)return Fail(C,E);
 if((W.InOut&3U)||(W.Cfg&0x3ffU)!=ConfigWord(0,1,1,0))return Fail(C,G202_ERR(7));
 for(uint32_t N=4;N;N--){uint32_t I=N-1,V=C->Before[I].Cfg;
  if(!(C->Touched&(1U<<I)))continue;
  E=Set(C,I,(V>>2)&15U,(V>>9)&1U,V&3U,(V>>6)&7U,(C->Before[I].InOut>>1)&1U);
  if(E)return E;C->Touched&=~(1U<<I);
 }
 C->Prepared=0;return 0;
}
