/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed root0 counterpart of selected OEM pci-msm.c:4966..5037.
 * Cold/reset/exclusive BYPASSED SRAM initialization or exact active table only.
 * Preserve CFG bits; enable translation last with endpoint BME held clear.
 * Never clear unknown ACTIVE stream bindings.
 */
#include "g403_platform.h"
#define CFG G403_SID_CFG
#define TABLE G403_SID_TABLE_BASE
static int fail(G403_RESULT*r,uint32_t code){r->Code=code;return (int)code;}
static uint8_t hash(uint16_t bdf){uint8_t crc=0;for(int j=1;j>=0;j--){crc^=(uint8_t)(bdf>>(j*8));for(unsigned k=0;k<8;k++)crc=(uint8_t)((crc&128)?(crc<<1)^7:crc<<1);}return crc;}
static int readtable(const G403_IO*i,uint32_t*t){for(unsigned n=0;n<256;n++)if(i->Read32(i->Context,TABLE+4*n,&t[n]))return 1;return 0;}
static int exact(const uint32_t*a,const uint32_t*b){for(unsigned n=0;n<256;n++)if(a[n]!=b[n])return 0;return 1;}
int G403PrepareSid(const G403_IO*i,G403_GATE gate,void*g,G403_RESULT*r){
 uint32_t current[256],snapshot[256],want[256]={0},cfg;
 if(!i||!i->Read32||!i->Write32||!gate||!r)return 1;
 if(r->Attempted||r->Prepared||r->Uncertain)return fail(r,2);
 r->Stage=1;if(gate(g))return fail(r,3);
 r->Hash=hash(0x100);r->Entry=0x01000100;want[r->Hash]=r->Entry;
 if(i->Read32(i->Context,CFG,&r->BeforeCfg)||r->BeforeCfg==UINT32_MAX||i->Read32(i->Context,UINT64_C(0x1c00234),&r->SidOffset)||readtable(i,r->Before)||readtable(i,current)||!exact(r->Before,current))return fail(r,4);
 /* Active translation may only reuse the exact desired table. A bypassed
  * stable table is inactive SRAM, admitted ONLY under caller's cold/reset
  * exclusive/no-consumer gate. Root RID0 is zero; RID0100 maps relativeSID1.
  */
 if(!(r->BeforeCfg&1)&&!exact(r->Before,want))return fail(r,5);
 r->Attempted=1;r->Stage=2;
 if(r->BeforeCfg&1){
  /* OEM memset_io clears exactly CRC8_TABLE_SIZE(256) words after reset.
   * Keep bypass asserted throughout; fresh full-progress/CFG checks reject
   * foreign changes before EVERY store, including stores of existing zero.
   */
  for(unsigned n=0;n<256;n++){
   if(gate(g)||readtable(i,snapshot)||!exact(snapshot,current)||
      i->Read32(i->Context,CFG,&cfg)||cfg!=r->BeforeCfg)return fail(r,6);
   r->Uncertain=1;r->Writes++;
   if(i->Write32(i->Context,TABLE+4*n,0)||
      i->Read32(i->Context,TABLE+4*n,&cfg)||cfg)return fail(r,7);
   current[n]=0;
  }
 }
 if(current[r->Hash]!=r->Entry){
  if(gate(g)||readtable(i,snapshot)||!exact(snapshot,current)||i->Read32(i->Context,CFG,&cfg)||cfg!=r->BeforeCfg)return fail(r,6);
  r->Uncertain=1;r->Writes++;
  if(i->Write32(i->Context,TABLE+4*r->Hash,r->Entry)||i->Read32(i->Context,TABLE+4*r->Hash,&cfg)||cfg!=r->Entry)return fail(r,7);
 }
 r->Stage=3;
 if(gate(g)||readtable(i,current)||!exact(current,want)||i->Read32(i->Context,CFG,&cfg)||cfg!=r->BeforeCfg)return fail(r,8);
 if(cfg&1){
  r->Uncertain=1;r->Writes++;
  if(i->Write32(i->Context,CFG,cfg&~1u))return fail(r,9);
 }
 r->Stage=4;
 if(i->Read32(i->Context,CFG,&r->AfterCfg)||r->AfterCfg!=(r->BeforeCfg&~1u)||readtable(i,r->After)||!exact(r->After,want)||gate(g))return fail(r,10);
 r->Uncertain=0;r->Prepared=1;r->Stage=5;return 0;
}
