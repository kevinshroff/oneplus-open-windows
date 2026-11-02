/* SPDX-License-Identifier: MIT
 * Only global and AP/ADSP shared-memory partitions may be selected.
 * No returned interval may escape the fixed SMEM reservation or overlap TOC.
 */
#ifndef G135_SELECT_H
#define G135_SELECT_H
#include <stdint.h>
#define G135_SMEM_BYTES 0x200000u
#define G135_PART_LIMIT 0x100000u
typedef struct {uint32_t Offset,Bytes,Host0,Host1,Cacheline;} G135_PART;
static uint16_t G135U16(const uint8_t*p){return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static uint32_t G135U32(const uint8_t*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int G135Select(const uint8_t*t,uint32_t bytes,G135_PART*out,uint32_t*count)
{
 uint32_t n,mask=0;*count=0;
 if(bytes!=4096||G135U32(t)!=0x434f5424u||G135U32(t+4)!=1)return 1;
 n=G135U32(t+8);if(!n||n>64)return 2;
 for(uint32_t i=0;i<n;i++){
  const uint8_t*p=t+32+48*i;uint32_t off=G135U32(p),size=G135U32(p+4),cl=G135U32(p+16);
  uint32_t h0=G135U16(p+12),h1=G135U16(p+14),selected=0;
  if(!off&&!size)continue;
  /* Actual firmware also lists its global header and TOC as metadata entries.
   * They are not processor-pair partitions and must never be selected. */
  if(h0==0xffff&&h1==0xffff){
   if(size!=4096||(off!=0&&off!=G135_SMEM_BYTES-4096))return 7;
   continue;
  }
  if(off<0x1000||!size||off>=G135_SMEM_BYTES-4096||size>G135_SMEM_BYTES-4096-off)return 3;
  for(uint32_t j=0;j<i;j++){
   const uint8_t*q=t+32+48*j;uint32_t a=G135U32(q),b=G135U32(q+4);
   if(G135U16(q+12)==0xffff&&G135U16(q+14)==0xffff)continue;
   if(a&&b&&off<a+b&&a<off+size)return 4;
  }
  if(h0==0xfffe&&h1==0xfffe)selected=1;
  if((h0==0&&h1==2)||(h0==2&&h1==0))selected=2;
  if(!selected)continue;
  if(mask&selected||size>G135_PART_LIMIT||(off&4095)||(size&4095)||cl<16||cl>256||(cl&(cl-1)))return 5;
  out[*count]=(G135_PART){off,size,h0,h1,cl};(*count)++;mask|=selected;
 }
 return mask==3?0:6;
}
static int G135PartHeader(const uint8_t*p,const G135_PART*x)
{
 uint32_t a=G135U32(p+12),b=G135U32(p+16);
 return G135U32(p)==0x54525024&&G135U16(p+4)==x->Host0&&G135U16(p+6)==x->Host1&&
 G135U32(p+8)==x->Bytes&&a>=32&&a<=b&&b<=x->Bytes;
}
#endif
