/* SPDX-License-Identifier: MIT. Independent native write/data-read admission. */
#ifndef G113_POLICY_H
#define G113_POLICY_H
#include "g113_core.h"
static inline unsigned G113Kind(unsigned n){return(n&1)?2u:1u;}
static inline uint32_t G113Payload(unsigned n){static const uint32_t registers[]={0x36,0x07,0x36};return registers[(n%6)/2];}
typedef struct{
 uint32_t Commands,Completed,Active,Held,Fed,Received,Faulted,Cancelled,Aborted,Writes;
 uint32_t Main[2],Status[2],TX[2],RX[2],IOS[2],TXLength[2],RXLength[2],Fresh,ID[2];
}G113_POLICY;
static inline int G113Controller(uint32_t at){
 for(unsigned i=0;i<1;i++)if(at>=G102Controllers[i].Base&&at-G102Controllers[i].Base<0x1000)return(int)i;
 return -1;
}
static inline int G113ReadAllowed(uint32_t at){return G102ReadAllowed(at)||at==0x880780;}
static inline void G113Observed(G113_POLICY*p,unsigned i,uint32_t o,uint32_t v){
 if(o==0x610)p->Main[i]=v;
 if(o==0x40){p->Status[i]=v;p->Fresh|=1u<<i;}
 if(o==0x800)p->TX[i]=v;
 if(o==0x804)p->RX[i]=v;
 if(o==0x908)p->IOS[i]=v;
 if(o==0x26c)p->TXLength[i]=v;
 if(o==0x780&&p->Commands&&((p->Commands-1)%6==1||(p->Commands-1)%6==5))p->ID[i]=v&0xff;
 if(o==0x270)p->RXLength[i]=v;
}
static inline int G113ReceiveAllowed(G113_POLICY*p,unsigned i){
 if(!p->Active||!p->Commands||i!=0||G113Kind(p->Commands-1)!=2||p->Received||p->RX[i]!=0x90000001u)return 0;
 p->Received=1;return 1;
}
static inline int G113WriteAllowed(G113_POLICY*p,unsigned i,uint32_t o,uint32_t v){
 uint32_t n=p->Commands,kind=G113Kind(n?n-1:0);
 if(i>=1||p->Writes>=512)return 0;
 if(o==0x26c){if(v!=1||p->Active||p->Held)return 0;p->TXLength[i]=v;}
 else if(o==0x270){if((v!=1&&v!=2)||p->Active)return 0;p->RXLength[i]=v;}
 else if(o==0x600){
  if(p->Faulted||p->Active||n!=p->Completed||n>=6||i!=0||!(p->Fresh&(1u<<i))||p->Status[i]||p->TX[i]||p->RX[i])return 0;
  uint32_t next=G113Kind(n);
  if(n>=2&&p->ID[i]!=0x67)return 0;
  uint32_t expected=next==0?0x0800de04u:next==1?0x0800de04u:0x1000de00u;
  if(v!=expected||(next==2?p->RXLength[i]!=1:p->TXLength[i]!=1))return 0;
  if((next==2)!=!!p->Held)return 0;
  p->Commands++;p->Active=1;p->Fed=p->Received=p->Cancelled=p->Aborted=0;p->Fresh&=~(1u<<i);
 }
 else if(o==0x700){
  if(!p->Active||!n||i!=0||kind==2||p->Fed||p->TX[i])return 0;
  if(v!=G113Payload(n-1))return 0;p->Fed=1;
 }
 else if(o==0x80c){if(v>1||(v==1&&(!p->Active||!n||i!=0||kind==2||p->Fed)))return 0;}
 else if(o==0x604){
  if(!n||i!=0||(!p->Active&&!p->Held))return 0;
  if(v==4){if(p->Cancelled)return 0;p->Cancelled=1;}
  else if(v==2){if(!p->Cancelled||p->Aborted)return 0;p->Aborted=1;}
  else return 0;p->Faulted=1;
 }
 else if(o==0x618){
  if(!v||(v&~G113_OWNED_IRQ)||(v&~p->Main[i]))return 0;
  if(n&&i==0&&(p->Active||p->Held)){
   int empty=(p->Fresh&(1u<<i))&&!p->Status[i]&&!p->TX[i]&&!p->RX[i];
   if((v&1)&&empty&&(kind==2?p->Received:p->Fed)){
    p->Completed++;p->Active=0;p->Held=kind==1;
   }else if((v&(G113_ERROR_IRQ|0x30))&&empty&&(p->IOS[i]&3)==3){p->Faulted=1;p->Active=p->Held=0;}
  }
  p->Main[i]&=~v;
 }
 else return 0;
 p->Writes++;return 1;
}
#endif
