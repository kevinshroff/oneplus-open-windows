/* SPDX-License-Identifier: MIT
 * Bounded discovery of the three AP/ADSP GLINK items, never an address API.
 */
#ifndef G158_SLOTS_H
#define G158_SLOTS_H
#include <stdint.h>
typedef struct {uint32_t Descriptor,Tx,Rx,Items,FreeUncached;} G158_SLOTS;
static inline uint32_t G158U16(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8;}
static inline uint32_t G158U32(const uint8_t*b){return G158U16(b)|(G158U16(b+2)<<16);}
static inline int G158FindSlots(const uint8_t*b,uint32_t n,G158_SLOTS*out)
{
 uint16_t ids[256];uint32_t count=0,found=0,at=32,free_u,free_c;
 G158_SLOTS v={0};
 if(!b||!out||n!=0x60000||b[0]!='$'||b[1]!='P'||b[2]!='R'||b[3]!='T'||
    G158U16(b+4)!=0||G158U16(b+6)!=2||G158U32(b+8)!=n)return 0;
 free_u=G158U32(b+12);free_c=G158U32(b+16);
 /* This diagnostic is bound to the native uncached heap, not other layouts. */
 if(free_u<32||free_u>n||free_c!=n)return 0;
 while(at<free_u){
  if(count==256||at>free_u-16||G158U16(b+at)!=0xa5a5)return 0;
  uint32_t id=G158U16(b+at+2),size=G158U32(b+at+4);
  uint32_t pad=G158U16(b+at+8),headerpad=G158U16(b+at+10);
  if(!size||size>n||pad>=size||headerpad>31||G158U32(b+at+12)||
     headerpad>free_u-at-16||size>free_u-at-16-headerpad)return 0;
  for(uint32_t j=0;j<count;j++)if(ids[j]==id)return 0;
  ids[count++]=(uint16_t)id;
  uint32_t data=at+16+headerpad,bytes=size-pad;
  if(id>=478&&id<=480){
   uint32_t bit=1u<<(id-478);if(found&bit||data&7||bytes!=(id==478?32u:16384u))return 0;
   found|=bit;if(id==478)v.Descriptor=data;else if(id==479)v.Tx=data;else v.Rx=data;
  }
  at=data+size;
 }
 if(at!=free_u||found!=7)return 0;
 v.Items=count;v.FreeUncached=free_u;*out=v;return 1;
}
#endif
