/* SPDX-License-Identifier: MIT */
#include "g70_client_policy.h"
static const uint16_t*Match(const uint16_t*p,const char*s){while(*s)if(*p++!=(uint8_t)*s++)return 0;return p;}
int G70ClientParse(const uint16_t*p,uint32_t*cycle,char nonce[33],uint64_t*value)
{
 const uint16_t*q;uint32_t i;uint64_t n=0;
 if(!p||!cycle||!nonce||!value||!*p)return 0;
 if(*p=='"'){p++;if(!*p||*p=='"')return 0;while(*p&&*p!='"')p++;if(!*p)return 0;p++;}
 else{if(*p==' ')return 0;while(*p&&*p!=' '){if(*p=='"')return 0;p++;}}
 if(*p!=' ')return 0;while(*p==' ')p++;
 if((q=Match(p,"query ")))*cycle=0;else if((q=Match(p,"cycle ")))*cycle=1;else return 0;
 p=q;while(*p==' ')p++;
 for(i=0;i<32;i++){
  uint16_t c=*p++;uint32_t digit;
  if(c>='0'&&c<='9')digit=c-'0';else if(c>='a'&&c<='f')digit=c-'a'+10;else return 0;
  nonce[i]=(char)c;if(i>=16)n=(n<<4)|digit;
 }
 if(*p||!n)return 0;nonce[32]=0;*value=n;return 1;
}
static int Zero(const void*p,uint32_t bytes){const uint8_t*b=p;for(uint32_t i=0;i<bytes;i++)if(b[i])return 0;return 1;}
int G70ClientReportShape(const G70_REPORT*r,uint32_t firmwareBytes)
{
 uint32_t index[4];if(!r)return 0;
 if(r->Size!=sizeof(*r)||r->Version!=1||r->Magic!=G70_MAGIC||r->KernelBuild!=26100||r->Processors!=8||r->Irql||r->FirmwareBytes!=firmwareBytes||r->FirmwareMatch!=1||r->FirmwareStatus)return 0;
 if(r->PrepareCalls!=1||r->ReleaseCalls||r->D0Entries!=1||r->D0Exits||r->InD0!=1||r->Removed)return 0;
 if(r->RawCount!=5||r->TranslatedCount!=5||r->ResourceOK!=1||r->MappingMask!=15||r->MapCalls!=4||r->UnmapCalls||r->Reserved)return 0;
 return G70ValidateControllerResources(r->Raw,r->Translated,index);
}
int G70ClientReadyForCycle(const G70_REPORT*r,uint32_t firmwareBytes)
{return G70ClientReportShape(r,firmwareBytes)&&!r->CycleAttempts&&Zero(&r->Clock,sizeof(r->Clock))&&Zero(&r->Probe,sizeof(r->Probe));}
int G70ClientCycleComplete(const G70_REPORT*r,uint32_t firmwareBytes,uint64_t nonce)
{
 static const uint32_t before[6]={0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002};
 static const uint32_t sequence[6]={0x40102380,0x40302380,0x44302380,0x40302380,0x40102380,0x40002380};
 const G70_CLOCK_RESULT*c;uint32_t i,reads=0,writes=0,waits=0;
 if(!nonce||!G70ClientReportShape(r,firmwareBytes)||r->CycleAttempts!=1)return 0;c=&r->Clock;
 if(c->Nonce!=nonce||c->Code||c->RestoreError||c->Restored!=1||c->Phase||c->DirtyMask||c->Active||c->Reads<35||c->Reads>64||c->Writes!=6||c->Waits>14||c->TraceCount>G70_EVENTS)return 0;
 for(i=0;i<6;i++)if(c->Before[i]!=before[i]||c->After[i]!=before[i])return 0;
 if(c->Enabled[0]!=0x44302380||c->Enabled[1]!=0x4000u||c->Enabled[2]!=0||c->Enabled[3]!=before[3])return 0;
 for(i=0;i<c->TraceCount;i++){
  const G70_EVENT*e=&c->Trace[i];
  if(e->Kind==1){
   if(e->Register>=6||(e->Phase!=1&&e->Phase!=2&&e->Phase!=3&&e->Phase!=90&&e->Phase!=91))return 0;
   if((e->Phase==2||e->Phase==90)&&e->Register)return 0;reads++;
  }
  else if(e->Kind==2){if(e->Register||writes>=6||e->Value!=sequence[writes]||e->Phase!=(writes<3?2u:90u))return 0;writes++;}
  else if(e->Kind==3){if(e->Register!=1||e->Value!=1||(e->Phase!=3&&e->Phase!=91))return 0;waits++;}
  else return 0;
 }
 if(r->Probe.Code||r->Probe.ReadCount!=20||r->Probe.CompletePasses!=2||r->Probe.IdentityMatch!=1||r->Probe.Stable!=1||r->Probe.Reserved)return 0;
 for(i=0;i<10;i++)if(r->Probe.First[i]!=G70EngineExpected[i]||r->Probe.Second[i]!=G70EngineExpected[i])return 0;
 return reads==c->Reads&&writes==c->Writes&&waits==c->Waits&&Zero(&c->Trace[c->TraceCount],(G70_EVENTS-c->TraceCount)*sizeof(G70_EVENT));
}
