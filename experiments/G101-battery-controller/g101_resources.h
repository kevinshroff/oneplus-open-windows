/* SPDX-License-Identifier: MIT; generated from pinned source. */
#ifndef G101_RESOURCES_H
#define G101_RESOURCES_H
#include <stdint.h>
typedef struct{uint32_t Vote,Mask,Cbcr,Hwcg;}G101_CLOCK;
typedef struct{uint32_t Base,Wrapper,Root,Pins[2],Mux[2];G101_CLOCK Clocks[3];}G101_CONTROLLER;
static const G101_CONTROLLER G101Controllers[2]={
 {0x880000,0x8c0000,0x11e010,{0,1},{2,2},{{0x152010,0x10,0x11e004,0},{0x152010,0x4,0x1233cc,1},{0x152010,0x2,0x1233d0,1}}},
 {0x98c000,0x9c0000,0x11705c,{22,23},{1,1},{{0x152008,0x2000,0x117058,0},{0x152008,0x100,0x123144,0},{0x152008,0x80,0x123140,1}}},
};
static const uint32_t G101Offsets[]={0x0,0x4,0x24,0x28,0x40,0x48,0x4c,0x64,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0x800,0x804,0xe24,0xe28,0x258};
/* Hub master exposes its own GENI_HW_PARAM at50h and fixed depth16.
 * No ordinary QUP wrapper-version or second FIFO parameter read is authorized. */
#define G101_SKIPPED 0xffffffffu
static inline uint32_t G101Offset(unsigned controller,unsigned slot){
 if(controller==1&&slot==17)return 0x50;
 if(controller==1&&slot==18)return G101_SKIPPED;
 return G101Offsets[slot];
}
#define G101_OFFSETS (sizeof(G101Offsets)/sizeof(G101Offsets[0]))
#endif
