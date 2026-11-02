/* SPDX-License-Identifier: MIT. Independent native write/data-read admission. */
#ifndef G103_POLICY_H
#define G103_POLICY_H
#include "g103_core.h"
typedef struct{
 uint32_t Commands,Completed,Active,Held,Fed,Received,Faulted,Cancelled,Aborted,Writes;
 uint32_t Main[2],Status[2],TX[2],RX[2],IOS[2],TXLength[2],RXLength[2],Fresh;
}G103_POLICY;
static inline int G103Controller(uint32_t at){
 for(unsigned i=0;i<2;i++)if(at>=G102Controllers[i].Base&&at-G102Controllers[i].Base<0x1000)return(int)i;
 return -1;
}
static inline int G103ReadAllowed(uint32_t at){return G102ReadAllowed(at)||at==0x880780||at==0x98c780;}
static inline void G103Observed(G103_POLICY*p,unsigned i,uint32_t o,uint32_t v){
 if(o==0x610)p->Main[i]=v;
 if(o==0x40){p->Status[i]=v;p->Fresh|=1u<<i;}
 if(o==0x800)p->TX[i]=v;
 if(o==0x804)p->RX[i]=v;
 if(o==0x908)p->IOS[i]=v;
 if(o==0x26c)p->TXLength[i]=v;
 if(o==0x270)p->RXLength[i]=v;
}
static inline int G103ReceiveAllowed(G103_POLICY*p,unsigned i){
 if(!p->Active||!p->Commands||i!=(p->Commands-1)/9||(p->Commands-1)%3!=2||p->Received||p->RX[i]!=0xa0000001u)return 0;
 p->Received=1;return 1;
}
static inline int G103WriteAllowed(G103_POLICY*p,unsigned i,uint32_t o,uint32_t v){
 uint32_t n=p->Commands,kind=n?n-1:0;kind%=3;
 if(i>=2||p->Writes>=256)return 0;
 if(o==0x26c){if((v!=1&&v!=3)||p->Active||p->Held)return 0;p->TXLength[i]=v;}
 else if(o==0x270){if(v!=2||p->Active)return 0;p->RXLength[i]=v;}
 else if(o==0x600){
  if(p->Faulted||p->Active||n!=p->Completed||n>=18||i!=n/9||!(p->Fresh&(1u<<i))||p->Status[i]||p->TX[i]||p->RX[i])return 0;
  uint32_t expected=n%3==0?0x0800aa00u:n%3==1?0x0800aa04u:0x1000aa00u;
  if(v!=expected||(n%3==2?p->RXLength[i]!=2:p->TXLength[i]!=(n%3==0?3u:1u)))return 0;
  if((n%3==2)!=!!p->Held)return 0;
  p->Commands++;p->Active=1;p->Fed=p->Received=p->Cancelled=p->Aborted=0;p->Fresh&=~(1u<<i);
 }
 else if(o==0x700){
  if(!p->Active||!n||i!=(n-1)/9||kind==2||p->Fed||p->TX[i])return 0;
  if(v!=(kind==0?(((n-1)%9)/3)<<8:0))return 0;p->Fed=1;
 }
 else if(o==0x80c){if(v>1||(v==1&&(!p->Active||!n||i!=(n-1)/9||kind==2||p->Fed)))return 0;}
 else if(o==0x604){
  if(!n||i!=(n-1)/9||(!p->Active&&!p->Held))return 0;
  if(v==4){if(p->Cancelled)return 0;p->Cancelled=1;}
  else if(v==2){if(!p->Cancelled||p->Aborted)return 0;p->Aborted=1;}
  else return 0;p->Faulted=1;
 }
 else if(o==0x618){
  if(!v||(v&~G103_OWNED_IRQ)||(v&~p->Main[i]))return 0;
  if(n&&i==(n-1)/9&&(p->Active||p->Held)){
   int empty=(p->Fresh&(1u<<i))&&!p->Status[i]&&!p->TX[i]&&!p->RX[i];
   if((v&1)&&empty&&(kind==2?p->Received:p->Fed)){
    p->Completed++;p->Active=0;p->Held=kind==1;
   }else if((v&(G103_ERROR_IRQ|0x30))&&empty&&(p->IOS[i]&3)==3){p->Faulted=1;p->Active=p->Held=0;}
  }
  p->Main[i]&=~v;
 }
 else return 0;
 p->Writes++;return 1;
}
#endif
