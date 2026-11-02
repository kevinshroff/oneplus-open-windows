/* SPDX-License-Identifier: MIT -- pure guards/decoder; never accesses hardware. */
#include "g74_client_policy.h"
static const char*Modes[6]={"status","snapshot","pmic","run","result","absent"};
const char*G74ClientMode(uint32_t mode){return mode<6?Modes[mode]:0;}
static const uint16_t*Match(const uint16_t*p,const char*s){while(*s)if(*p++!=(uint8_t)*s++)return 0;return p;}
int G74ClientParse(const uint16_t*p,uint32_t*mode,char nonce[33],uint64_t*value)
{
 if(!p||!mode||!nonce||!value||!*p)return 0;
 if(*p=='"'){p++;if(!*p||*p=='"')return 0;while(*p&&*p!='"')p++;if(!*p)return 0;p++;}
 else{if(*p==' ')return 0;while(*p&&*p!=' '){if(*p=='"')return 0;p++;}}
 if(*p!=' ')return 0;while(*p==' ')p++;
 uint32_t m;const uint16_t*q=0;for(m=0;m<6;m++){q=Match(p,Modes[m]);if(q&&*q==' ')break;}if(m==6)return 0;p=q;while(*p==' ')p++;
 uint64_t n=0;for(uint32_t i=0;i<32;i++){uint16_t c=*p++;uint32_t d;if(c>='0'&&c<='9')d=c-'0';else if(c>='a'&&c<='f')d=c-'a'+10;else return 0;nonce[i]=(char)c;if(i>=16)n=(n<<4)|d;}
 if(*p||!n)return 0;nonce[32]=0;*mode=m;*value=n;return 1;
}
static int Zero(const void*p,uint32_t n){const uint8_t*b=p;for(uint32_t i=0;i<n;i++)if(b[i])return 0;return 1;}
int G74ClientStatus(const G74_STATUS*s)
{
 static const uint8_t id[16]="G74-off-meta1";
 if(!s||s->Size!=96||s->Version!=1||s->Magic!=G74_MAGIC||s->KernelBuild!=26100||s->Processors!=8||s->CurrentIrql||s->FirmwareBytes!=576||s->FirmwareMatch!=1||s->FirmwareStatus||s->RegisterCount!=50||s->MapCalls>128||!s->Sequence)return 0;
 if(s->RunAttempts>1||s->ObserverCaptures>5||s->ObserverFault>1||s->OffPmicVerified>1)return 0;
 for(uint32_t i=0;i<16;i++)if(s->BuildId[i]!=id[i])return 0;return 1;
}
int G74ClientReady(const G74_STATUS*s)
{return G74ClientStatus(s)&&s->MapCalls>=18&&!s->RunAttempts&&s->ObserverCaptures==1&&!s->ObserverFault&&s->OffPmicVerified==1;}
static int Fixed(const uint32_t*p,const uint32_t expected[50])
{for(uint32_t i=0;i<50;i++){if(i==12){if(p[i]!=0&&p[i]!=7)return 0;}else if(p[i]!=expected[i])return 0;}return 1;}
int G74ClientSnapshot(const G74_SNAPSHOT*p,const uint32_t expected[50])
{return p&&expected&&G74ClientStatus(&p->Status)&&p->Count==50&&!p->Reserved&&Fixed(p->Values,expected);}
static int Pmic(const G74_OBS_RESULT*p)
{
 static const uint8_t cfg[8]={8,7,0,0,7,7,0,0},revision[8]={32,0,0,2,81,73,1,0},anchor[8]={0,4,1,1,4,172,0,0},identity[8]={0,4,1,1,4,171,0,0};
 if(p->Code||p->Stage||p->Status!=0x43||p->Writes!=5||p->Commands!=5||p->Reads<36||p->Reads>91||p->TraceCount>128||p->TraceCount!=p->Reads+p->Writes||p->Polls<5||p->Polls>60||p->Reads!=31+p->Polls)return 0;
 for(uint32_t i=0;i<8;i++)if(p->Configuration[i]!=cfg[i]||p->Revision[i]!=revision[i]||p->Anchor[i]!=anchor[i]||p->Identity[i]!=identity[i])return 0;
 for(uint32_t i=0;i<5;i++)if(p->Completion[i]!=1)return 0;
 const uint32_t address[5]={0xc440ea0,0xc441220,0xc4456e0,0xc4456e0,0xc4456e0},command[5]={0x08000007,0x08000007,0x08000007,0x08000080,0x08000407};uint32_t reads=0,writes=0;
 for(uint32_t i=0;i<p->TraceCount;i++){
  const G74_OBS_EVENT*e=p->Trace+i;
  if(e->Kind==1){reads++;}
  else if(e->Kind==2){if(writes>=5||e->Address!=address[writes]||e->Value!=command[writes])return 0;writes++;}
  else return 0;
 }
 if(reads!=p->Reads||writes!=5)return 0;
 return Zero(p->Reserved,3)&&Zero(p->Trace+p->TraceCount,(128-p->TraceCount)*sizeof(*p->Trace));
}
int G74ClientPmic(const G74_PMIC*p)
{return p&&G74ClientStatus(&p->Status)&&p->Status.OffPmicVerified==1&&!p->Status.ObserverFault&&p->FixedRegistersUnchanged==1&&(p->Attempt==1||p->Attempt==2)&&!p->Reserved&&p->CounterFrequency==19200000&&p->ElapsedTicks&&Pmic(&p->Observer);}
int G74ClientRun(const G74_RUN*p,const uint32_t expected[50],uint64_t nonce)
{
 if(!p||!expected||!nonce||!G74ClientStatus(&p->Status)||p->Status.MapCalls<36||p->Status.RunAttempts!=1||p->Status.ObserverCaptures!=4||p->Status.ObserverFault||p->Status.OffPmicVerified!=1||p->Nonce!=nonce||p->Attempt!=1||p->Reserved||p->BaselineValid!=1||p->FixedRegistersUnchanged!=1||p->CounterFrequency!=19200000||!p->ElapsedTicks||!Fixed(p->Before,expected))return 0;
 for(uint32_t i=0;i<50;i++)if(p->Before[i]!=p->After[i])return 0;
 const G74_OFF_RESULT*r=&p->Off;uint32_t count=p->Before[12]==7?11:10;
 if(r->Code||r->RestoreError||r->Restored!=1||r->Stage||r->TxnCount!=count||r->PmicCount!=3||r->PreflightVerified!=1||r->FlipAttempted!=1||r->RestoreAttempted!=1||r->FlipVerified!=1||r->OriginalVerified!=1||r->RscUncertain||r->ObserverUncertain||r->OffVerified!=1||r->AckRaw!=0x80000000u||r->NoAckRaw||r->Waits1ms>count*23||r->LastOffWriteTxn!=6||r->LastOffObserveTxn!=count)return 0;
 const uint32_t vote[3]={1800,7,0},guard[8]={1,0,0x201,0,1,0,0xe2,0};
 for(uint32_t i=0;i<3;i++)if(r->ClientBefore[i]!=vote[i]||r->ClientAfter[i]!=vote[i]||!Pmic(r->Pmic+i))return 0;
 for(uint32_t i=0;i<8;i++)if(r->GuardBefore[i]!=guard[i]||r->GuardAfter[i]!=guard[i])return 0;
 const uint32_t address[11]={0x40800,0x40808,0x40804,0x40804,0x40804,0x40804,0x40804,0x40800,0x40808,0x40804,0x40808};
 const uint32_t response[11]={1800,7,0,0,0x80000000u,0,0,1800,7,0,7};
 for(uint32_t i=0;i<count;i++){
  const G74_RSC_RESULT*t=r->Transactions+i;uint32_t msg=i==3?0x10108u:i==5?0x10008u:0x108u;
  if(t->Code||t->RestoreError||t->Restored!=1||t->Stage||t->Writes!=14||t->Reads>192||t->TraceCount>256||t->TraceCount!=t->Reads+t->Writes||t->RequestAddress!=address[i]||t->RequestData||t->MsgId!=msg||t->Response!=response[i]||t->Triggered!=1||t->Mutated!=1||(i==5?t->Completion!=0x101u:(t->Completion&0x10100)!=0x10100))return 0;
  for(uint32_t j=0;j<17;j++)if(j!=12&&t->Before[j]!=t->After[j])return 0;
  const uint32_t wa[14]={0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d2c,0x17a20d24,0x17a20d24,0x17a20d24,0x17a20d24,0x17a20d24,0x17a20d2c,0x17a20d08,0x17a20d34,0x17a20d38,0x17a20d3c};
  const uint32_t wv[14]={msg,address[i],0,1,0x10000,0x10000,0x1010000,0x10000,0,0,1,t->Before[8],t->Before[9],t->Before[10]};uint32_t reads=0,writes=0;
  for(uint32_t j=0;j<t->TraceCount;j++){
   const G74_RSC_EVENT*e=t->Trace+j;
   if(e->Kind==1){reads++;}
   else if(e->Kind==2){if(writes>=14||e->Address!=wa[writes]||e->Value!=wv[writes])return 0;writes++;}
   else return 0;
  }
  if(reads!=t->Reads||writes!=14)return 0;
  if(!Zero(t->Trace+t->TraceCount,(256-t->TraceCount)*sizeof(*t->Trace)))return 0;
 }
 return Zero(r->Transactions+count,(12-count)*sizeof(*r->Transactions));
}
