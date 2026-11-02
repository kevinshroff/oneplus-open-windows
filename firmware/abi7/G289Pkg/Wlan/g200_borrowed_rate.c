/* GPL-2.0-only: G371 exact voted GPLL0/Lucid OLE and local RCG2 tuple.
 * Bounded pure readback validation; no register writes/provider invocation.
 * MODE, OPMODE, L, ALPHA, USER_CTL, RCG CMD/CFG, branch AP vote/CBCR, PLL AP vote.
 * The exact USER_CTL bit25 path enables by vote+LOCK/RESET polling and bypasses
 * non-FSM OPMODE/mask7 programming. Do not apply that other branch's predicates.
 */
#include "g200_clock.h"
G200_STATUS G200ValidateRateTuple(const uint32_t W[2][10],uint32_t*Hz){
 if(!W||!Hz)return G200_INVALID;
 for(uint32_t I=0;I<10;I++)if(W[0][I]!=W[1][I])return G200_NOT_READY;
 const uint32_t*S=W[0];
 if(!(S[4]&(1U<<25))||(S[0]&0x80000004U)!=0x80000004U||
    (S[0]&(1U<<14)))return G200_NOT_READY;
 if(((S[4]>>10)&15U)!=1U||S[3]>0xffffU)return G200_NOT_READY;
 uint64_t PllQ16=UINT64_C(19200000)*(((uint64_t)(S[2]&0xffffU)<<16)+S[3]);
 if(PllQ16!=UINT64_C(600000000)*65536U)return G200_NOT_READY;
 if((S[5]&0x80000001U)||!(S[7]&(1U<<22))||(S[8]&0x80000000U))return G200_NOT_READY;
 /* Bit20 is a mode distinction, not a frequency/sleep-completion witness. */
 uint32_t Cfg=S[6]&0x371fU;
 if(Cfg==0)*Hz=19200000;
 else if(Cfg==0x605U)*Hz=100000000;
 else return G200_NOT_READY;
 return G200_OK;
}
