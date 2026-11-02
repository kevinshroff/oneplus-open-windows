/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "g158_slots.h"
static uint8_t Original[0x60000],Data[0x60000];
static void Put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
int main(int argc,char**argv)
{
 assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f&&fread(Original,1,sizeof(Original),f)==sizeof(Original)&&fgetc(f)==EOF);fclose(f);
 G158_SLOTS slots={0},out;unsigned cases=0;
 assert(G158FindSlots(Original,sizeof(Original),&slots)&&slots.Items==11&&slots.Descriptor==48&&slots.Tx==96);cases++;
 for(unsigned offset=0;offset<20;offset++){
  memcpy(Data,Original,sizeof(Data));Data[offset]^=0x80;out=slots;
  assert(!G158FindSlots(Data,sizeof(Data),&out)&&!memcmp(&out,&slots,sizeof(out)));cases++;
 }
 for(unsigned mode=0;mode<12;mode++){
  memcpy(Data,Original,sizeof(Data));
  uint32_t h=slots.Descriptor-16;
  if(mode==0)Data[h]^=1;
  if(mode==1)Put32(Data+h+4,0xffffffff);
  if(mode==2)Put32(Data+h+4,31);
  if(mode==3)Data[h+8]=32;
  if(mode==4)Data[h+10]=32;
  if(mode==5)Data[h+12]=1;
  if(mode==6){Data[slots.Tx-14]=0xde;Data[slots.Tx-13]=1;} /* duplicate478 */
  if(mode==7){Data[slots.Rx-14]=0xe1;Data[slots.Rx-13]=1;} /* missing480 */
  if(mode==8)Put32(Data+12,slots.FreeUncached-1);
  if(mode==9)Put32(Data+16,sizeof(Data)-32);
  if(mode==10)Put32(Data+12,33);
  if(mode==11)Put32(Data+12,0xffffffff);
  out=slots;assert(!G158FindSlots(Data,sizeof(Data),&out)&&!memcmp(&out,&slots,sizeof(out)));cases++;
 }
 /* Live counter/data changes in unrelated items do not move the known rings. */
 memcpy(Data,Original,sizeof(Data));Data[0x972c]^=0x80;assert(G158FindSlots(Data,sizeof(Data),&out)&&!memcmp(&out,&slots,sizeof(out)));cases++;
 /* A valid appended item is permitted, while no existing ring is reallocated. */
 memcpy(Data,Original,sizeof(Data));uint32_t at=slots.FreeUncached;Data[at]=0xa5;Data[at+1]=0xa5;Data[at+2]=0xfe;Data[at+3]=3;Put32(Data+at+4,8);Put32(Data+12,at+24);
 assert(G158FindSlots(Data,sizeof(Data),&out)&&out.Items==12&&out.Tx==slots.Tx&&out.Rx==slots.Rx&&out.Descriptor==slots.Descriptor);cases++;
 assert(!G158FindSlots(NULL,sizeof(Data),&out));cases++;
 assert(!G158FindSlots(Data,32,&out));cases++;
 assert(!G158FindSlots(Data,sizeof(Data),NULL));cases++;
 /* Deterministic hostile header values exercise arithmetic under sanitizers. */
 for(unsigned i=0;i<256;i++){
  memcpy(Data,Original,sizeof(Data));Put32(Data+slots.Tx-12,0xffff0000u+i*257u);assert(!G158FindSlots(Data,sizeof(Data),&out));cases++;
 }
 printf("{\"passed\":true,\"cases\":%u,\"native_operations\":0}\n",cases);return 0;
}
