/* SPDX-License-Identifier: MIT
 * Pure fixedLucidOLE(main) predicate from selected source/G371 rate proof.
 * Voted USER25 bypasses nonvoted OPMODE/outputmask predicates. Main output
 * does not use WiFi's EVEN/2 postdivider. No reprogramming fallback.
 */
#ifndef G400_GPLL0_POLICY_H
#define G400_GPLL0_POLICY_H
#include <stdint.h>
static inline int G400PllStable600(const uint32_t w[2][6])
{
 for(unsigned j=0;j<6;j++) if(w[0][j]!=w[1][j]||w[0][j]==UINT32_MAX) return 0;
 const uint32_t*s=w[0];
 if(!(s[4]&(1u<<25))||(s[0]&0x80000004u)!=0x80000004u||s[3]>0xffffu) return 0;
 uint64_t q=UINT64_C(19200000)*(((uint64_t)(s[2]&0xffffu)<<16)+s[3]);
 return q==UINT64_C(600000000)*65536u;
}
#endif
