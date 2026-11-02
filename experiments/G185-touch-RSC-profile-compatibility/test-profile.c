#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "g98_power.h"
#include "g98_rsc_profile.h"
static const uint32_t A[17]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08};
static const uint32_t B[17]={0x30000,0x4010100,0x800c8104,1,0,1,0,0,0x10108,0x50008,0x60000001,0,7,0,0,0,0};
typedef struct {uint32_t Reg[17],Before[17];unsigned Reads,Writes,FailRead,FailWrite,Ambiguous,Foreign,ForeignSeen,ForeignWrites;G98_RSC_RESULT*r;} MODEL;
static int Read(void*x,uint32_t at,uint32_t*v){MODEL*m=x;if(++m->Reads==m->FailRead)return 0;unsigned i;for(i=0;i<17;i++)if(A[i]==at)break;assert(i<17);
 if(m->Foreign&&!m->ForeignSeen&&m->r->Stage==90&&i==9){m->Reg[9]=m->Before[9]==0x50008?0x50000:0x50008;m->ForeignSeen=1;}
 *v=m->Reg[i];return 1;
}
static int Write(void*x,uint32_t at,uint32_t v){MODEL*m=x;m->Writes++;if(m->ForeignSeen)m->ForeignWrites++;assert(G98RscWriteAllowed(at,v));if(m->Writes==m->FailWrite&&!m->Ambiguous)return 0;
 if(at==0x17a20d08){m->Reg[4]=0;m->Reg[11]=0;}
 else{unsigned i;for(i=0;i<17;i++)if(A[i]==at)break;assert(i<17);
  if(i>=8&&i<=10&&v==m->Before[i])assert(!m->Reg[6]&&!m->Reg[7]&&m->Reg[5]==1);
  m->Reg[i]=v;
  if(i==6&&v==0x1010000){assert(m->Reg[7]==1);m->Reg[4]=1;m->Reg[5]=1;m->Reg[6]=0x10000;m->Reg[11]=m->Reg[8]==0x10008?0x101:0x10101;m->Reg[12]=1800;}
 }
 return m->Writes!=m->FailWrite;
}
static void Wait(void*x){(void)x;}
static void Reset(MODEL*m,G98_RSC_RESULT*r,unsigned profile){memset(m,0,sizeof(*m));memset(r,0,sizeof(*r));m->r=r;memcpy(m->Reg,B,sizeof(B));if(profile){m->Reg[9]=0x50000;m->Reg[10]=0x600626ac;}memcpy(m->Before,m->Reg,sizeof(m->Reg));}
static unsigned Cases;
static void Run(MODEL*m,G98_RSC_RESULT*r,unsigned mode){G98_RSC_IO io={m,Read,Write,Wait};uint32_t address=mode<3?0x40800+4*mode:0x40804;unsigned op=mode<3?G98_READ:mode==3?G98_OFF_ACK:mode==4?G98_OFF_NO_ACK:G98_ON_ACK;G98Transfer(&io,r,address,op==G98_ON_ACK?1:0,op);if(r->Restored)assert(!memcmp(m->Before,m->Reg,11*sizeof(uint32_t)));Cases++;}
typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef size_t SIZE_T;
#include "g98_binding.h"
/* The following marker is replaced with the actual two wrapper functions. */
/* ACTUAL_FIXED_BASELINE_FUNCTIONS */
int main(void){MODEL m;G98_RSC_RESULT r;
 for(unsigned p=0;p<2;p++)for(unsigned mode=0;mode<6;mode++){
  Reset(&m,&r,p);Run(&m,&r,mode);assert(!r.Code&&r.Restored&&!r.RestoreError&&r.Triggered);unsigned writes=m.Writes,reads=m.Reads;
  for(unsigned n=1;n<=writes;n++)for(unsigned ambiguous=0;ambiguous<2;ambiguous++){Reset(&m,&r,p);m.FailWrite=n;m.Ambiguous=ambiguous;Run(&m,&r,mode);assert(r.Code||r.RestoreError);}
  for(unsigned n=1;n<=reads;n++){Reset(&m,&r,p);m.FailRead=n;Run(&m,&r,mode);assert(r.Code||r.RestoreError);}
  Reset(&m,&r,p);m.Foreign=1;Run(&m,&r,mode);assert(r.RestoreError==3&&!r.Restored&&m.ForeignSeen&&!m.ForeignWrites);
 }
 for(unsigned p=0;p<2;p++){
  uint32_t words[50];memcpy(words,G98ExpectedValues,sizeof(words));if(p){words[9]=0x50000;words[10]=0x600626ac;}assert(G98FixedBaseline(words));Cases++;
  for(unsigned i=0;i<50;i++)if(i!=12)for(unsigned b=0;b<32;b++){words[i]^=1u<<b;assert(!G98FixedBaseline(words));words[i]^=1u<<b;Cases++;}
  words[12]=0;assert(G98FixedBaseline(words));words[12]=7;assert(G98FixedBaseline(words));words[12]=8;assert(!G98FixedBaseline(words));Cases+=3;
  uint32_t other[50];memcpy(other,words,sizeof(words));words[12]=other[12]=7;other[9]=p?0x50008:0x50000;other[10]=p?0x60000001:0x600626ac;assert(G98FixedBaseline(words)&&G98FixedBaseline(other)&&!G98FixedSameRestorable(words,other));Cases++;
 }
 for(unsigned p=0;p<2;p++)for(unsigned b=0;b<32;b++)for(unsigned at=9;at<=10;at++){Reset(&m,&r,p);m.Reg[at]^=1u<<b;Run(&m,&r,0);assert(r.Code==2&&!r.Mutated&&!m.Writes);}
 printf("{\"passed\":true,\"actual_RSC_and_snapshot_cases\":%u,\"native_operations\":0}\n",Cases);
}
