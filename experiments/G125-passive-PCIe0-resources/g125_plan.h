/* SPDX-License-Identifier: MIT
 * Fixed root0 GCC/TLMM passive plan. No peripheral/PARF/PHY/ECAM reads.
 */
#ifndef G125_PLAN_H
#define G125_PLAN_H
#define G125_PAGE_COUNT 7u
#define G125_WORD_COUNT 24u
#define G125_FULL_WORD_MASK 0x00ffffffu
#define G125_UNSUITABLE_CONTROL 0x123cu
static const ULONGLONG G125Pages[G125_PAGE_COUNT]={0x152000ULL,0x16b000ULL,0x16c000ULL,0xf153000ULL,0xf15e000ULL,0xf160000ULL,0xf150000ULL};
typedef struct{ULONG Page,Offset;}G125_WORD;
static const G125_WORD G125Words[G125_WORD_COUNT]={
 {0u,0x20u}, /* collapse_vote */
 {0u,0x0u}, /* clock_vote_52000 */
 {0u,0x8u}, /* clock_vote_52008 */
 {1u,0x0u}, /* core_reset */
 {1u,0x4u}, /* core_gdscr */
 {1u,0x8u}, /* core_cfg_gdscr */
 {1u,0x1cu}, /* slv_q2a_cbcr */
 {1u,0x20u}, /* slv_axi_cbcr */
 {1u,0x2cu}, /* mstr_axi_cbcr */
 {1u,0x38u}, /* cfg_ahb_cbcr */
 {1u,0x3cu}, /* aux_cbcr */
 {1u,0x48u}, /* pipe_cbcr */
 {1u,0x54u}, /* rate_change_cbcr */
 {2u,0x0u}, /* phy_gdscr */
 {2u,0x4u}, /* phy_cfg_gdscr */
 {2u,0x1cu}, /* phy_reset */
 {3u,0x0u}, /* selector_control */
 {3u,0x4u}, /* selector_inout */
 {4u,0x0u}, /* perst_control */
 {4u,0x4u}, /* perst_inout */
 {5u,0x0u}, /* wake_control */
 {5u,0x4u}, /* wake_inout */
 {6u,0x0u}, /* wlan_enable_control */
 {6u,0x4u}, /* wlan_enable_inout */
};
static ULONG G125SelectionCode(const ULONG samples[2][G125_WORD_COUNT]){
 if((samples[0][16]|samples[1][16])&G125_UNSUITABLE_CONTROL)return 2001;
 if(samples[0][16]!=samples[1][16]||samples[0][17]!=samples[1][17])return 2002;
 if(samples[0][17]&1)return 2003;
 return 0;
}
#endif
