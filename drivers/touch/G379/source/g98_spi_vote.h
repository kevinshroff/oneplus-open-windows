/* SPDX-License-Identifier: MIT */
#ifndef G98_SPI_VOTE_H
#define G98_SPI_VOTE_H
#include <stdint.h>
#define G98_SPI_VOTE_MASK 0x04300000u
#define G98_SPI_VOTE_REQUIRED 0x40002380u
static inline int G98SpiVoteBaseline(uint32_t before)
{
 return !(before&G98_SPI_VOTE_MASK)&&(before&G98_SPI_VOTE_REQUIRED)==G98_SPI_VOTE_REQUIRED;
}
/* Only the three existing QUP votes, in original forward/reverse order.
 * Every other bit must equal the operation's immutable initial capture. */
static inline int G98SpiVoteTransition(uint32_t before,uint32_t expected,uint32_t value)
{
 uint32_t a=expected&G98_SPI_VOTE_MASK,b=value&G98_SPI_VOTE_MASK;
 if(!G98SpiVoteBaseline(before)||(expected&~G98_SPI_VOTE_MASK)!=before||(value&~G98_SPI_VOTE_MASK)!=before)return 0;
 return (a==0&&b==0x00100000u)||(a==0x00100000u&&(b==0||b==0x00300000u))||
        (a==0x00300000u&&(b==0x00100000u||b==G98_SPI_VOTE_MASK))||
        (a==G98_SPI_VOTE_MASK&&b==0x00300000u);
}
#endif
