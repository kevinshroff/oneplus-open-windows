/* SPDX-License-Identifier: MIT
 * Exact Open branch-enable admission. Not an instantaneous toggling-clock proof.
 * Indices match fixed OGPR gate addresses; never apply to an arbitrary branch.
 */
#ifndef G323_CLOCK_POLICY_H
#define G323_CLOCK_POLICY_H
static inline int G323BranchReady(unsigned index,unsigned value)
{
 if(value==0xffffffffu||!(value&1u)) return 0;
 if(index==3u) return (value&2u)||!(value&0x80000000u); /* MEMNOC HWCG bit1 */
 if(index==4u||index==5u) return 1; /* source HALT_DELAY after10us */
 if(index==6u) return !(value&0x80000000u); /* SMMU HALT_VOTED, no HWCG */
 return 0;
}
#endif
