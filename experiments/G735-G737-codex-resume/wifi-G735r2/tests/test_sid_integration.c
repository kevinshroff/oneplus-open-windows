#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "g735_smmu_identity.h"
static uint32_t table[256],cfg,writes,reads;
static uint64_t last_read;
static int read32(void*c,uint64_t a,uint32_t*v){
 (void)c;reads++;last_read=a;
 if(a==G403_SID_CFG){*v=cfg;return 0;}
 if(a==UINT64_C(0x1c00234)){*v=0x1400;return 0;}
 if(a>=G403_SID_TABLE_BASE&&a<G403_SID_TABLE_BASE+sizeof(table)&&!(a&3)){*v=table[(a-G403_SID_TABLE_BASE)/4];return 0;}
 return 1;
}
static int write32(void*c,uint64_t a,uint32_t v){
 (void)c;writes++;
 if(a==G403_SID_CFG){cfg=v;return 0;}
 if(a>=G403_SID_TABLE_BASE&&a<G403_SID_TABLE_BASE+sizeof(table)&&!(a&3)){table[(a-G403_SID_TABLE_BASE)/4]=v;return 0;}
 return 1;
}
static int gate(void*c){(void)c;return 0;}
int main(void){
 G403_IO io={0,read32,write32};G403_RESULT sid={0};G735_RESULT r;
 memset(table,0,sizeof(table));cfg=1;
 /* Run the retained actual producer, including its CRC and programming path. */
 assert(!G403PrepareSid(&io,gate,0,&sid));
 assert(sid.Prepared&&sid.Stage==5&&sid.Hash==0x15&&sid.Entry==0x01000100u);
 assert(table[sid.Hash]==sid.Entry&&table[0x0f]==0&&cfg==0);
 uint32_t before=writes;G735Init(&r);assert(!G735VerifyPreparedSid(&io,&sid,&r));
 assert(writes==before&&r.SidHash==sid.Hash&&r.SidTableAddress==G403_SID_TABLE_BASE+4*sid.Hash);
 assert(r.SidTableAddress==UINT64_C(0x1c02054)&&last_read==r.SidTableAddress&&r.SidEntry==sid.Entry);
 /* Merely populating the formerly invented wrong slot cannot admit DMA. */
 table[0x0f]=sid.Entry;table[sid.Hash]=0;G735Init(&r);
 assert(G735VerifyPreparedSid(&io,&sid,&r)&&r.GateCode==3&&writes==before);
 table[sid.Hash]=sid.Entry;cfg=1;G735Init(&r);
 assert(G735VerifyPreparedSid(&io,&sid,&r)&&r.GateCode==2);
 cfg=0;sid.After[sid.Hash]=0;uint32_t oldreads=reads;G735Init(&r);
 assert(G735VerifyPreparedSid(&io,&sid,&r)&&reads==oldreads);
 sid.After[sid.Hash]=sid.Entry;sid.Stage=4;G735Init(&r);
 assert(G735VerifyPreparedSid(&io,&sid,&r)&&reads==oldreads);
 sid.Stage=5;sid.Prepared=0;G735Init(&r);
 assert(G735VerifyPreparedSid(&io,&sid,&r)&&reads==oldreads);
 puts("actual G403 CRC/preparation -> G735 SID guard integration passed");return 0;
}
