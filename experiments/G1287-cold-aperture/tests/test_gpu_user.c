#include "gpu_user_bank.h"
#include "fault_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {OSH_SNAPSHOT S;unsigned Reads,Deny,Busy,Drift;}MODEL;
static void init(MODEL*m){memset(m,0,sizeof(*m));m->S.Id0=0x4c017e18;m->S.Id1=0x40000016;m->S.Id2=0x5511;m->S.Nscr0=0x2f0406;m->S.Nsacr=0x1c;for(unsigned k=0;k<24;k++)m->S.S2cr[k]=0x20000;}
static int current(void*x,uint64_t g,uint64_t s){return ((MODEL*)x)->Deny||g!=7||s!=19;}
static int snapshot(void*x,OSH_SNAPSHOT*s){*s=((MODEL*)x)->S;return 0;}
static int readcb(void*x,unsigned bank,uint32_t*v){MODEL*m=x;assert(bank==0);m->Reads++;*v=m->Busy?1:m->Drift?m->Reads:0;return 0;}
static OLB_IO io(MODEL*m){OLB_IO o={m,current,snapshot,readcb};return o;}
int main(void){MODEL m;OGU_BANK b;OLB_IO o;unsigned n=0;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);assert(OguReserve(&b,&o,7,19,0,4)==OLB_OK&&b.Slot==1&&b.Qualified&&m.Reads==2);assert(OguCheckCold(&b,&o)==OLB_OK);assert(OguReserve(&b,&o,7,19,0,5)==OLB_ARGUMENT);n++;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);m.S.Smr[7]=0x80000002;m.S.S2cr[7]=9;assert(OguReserve(&b,&o,7,19,0,4)==OLB_PROFILE&&!m.Reads&&!b.Id);n++;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);m.S.Smr[3]=0x80000000;assert(OguReserve(&b,&o,7,19,0,4)==OLB_PROFILE&&!m.Reads);n++;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);m.Deny=1;assert(OguReserve(&b,&o,7,19,0,4)==OLB_CURRENT&&!m.Reads);n++;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);m.Busy=1;assert(OguReserve(&b,&o,7,19,0,4)==OLB_BUSY&&!b.Id);n++;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);m.Drift=1;assert(OguReserve(&b,&o,7,19,0,4)==OLB_IO_ERROR&&!b.Id);n++;
 init(&m);memset(&b,0,sizeof(b));o=io(&m);assert(!OguReserve(&b,&o,7,19,0,4));b.Retained=1;assert(OguCheckCold(&b,&o)==OLB_TOKEN);n++;
 OF_JOURNAL j={0};assert(OfAckPolicy(&j,2,0x20)==0x20&&j.Fatal&&j.LastStatus[2]==0x20);assert(OfAckPolicy(&j,3,0x80)==0&&j.AckWrites==1);n++;
 printf("PASS %u focused actual-body cases; explicit host owner/MMIO model, no native evidence\n",n);return 0;}
