/* SPDX-License-Identifier: MIT -- actual adapter model fixture, not native. */
#include "g74_client_policy.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
static unsigned Cases;
static uint32_t Expected[50];
static int Complete(const G74_RUN*p){return G74ClientRun(p,Expected,42);}
static int Parse(const char*s){uint16_t c[256];uint32_t mode;char nonce[33];uint64_t n;size_t len=strlen(s);assert(len<256);for(size_t i=0;i<=len;i++)c[i]=(uint8_t)s[i];return G74ClientParse(c,&mode,nonce,&n);}
int main(int argc,char**argv)
{
 assert(argc==3);G74_RUN original,r;FILE*f=fopen(argv[1],"rb");assert(f&&fread(&original,1,sizeof(original),f)==sizeof(original)&&fgetc(f)==EOF&&!fclose(f));f=fopen(argv[2],"rb");assert(f&&fread(Expected,4,50,f)==50&&fgetc(f)==EOF&&!fclose(f));assert(Complete(&original));Cases++;
 G74_STATUS ready=original.Status;ready.RunAttempts=0;ready.ObserverCaptures=1;ready.MapCalls=18;assert(G74ClientReady(&ready)&&!G74ClientReady(&original.Status));Cases++;
 G74_SNAPSHOT snap;memset(&snap,0,sizeof(snap));snap.Status=ready;snap.Count=50;memcpy(snap.Values,Expected,200);assert(G74ClientSnapshot(&snap,Expected));Cases++;
 G74_PMIC pm;memset(&pm,0,sizeof(pm));pm.Status=ready;pm.Observer=original.Off.Pmic[0];pm.FixedRegistersUnchanged=pm.Attempt=1;pm.CounterFrequency=19200000;pm.ElapsedTicks=1;assert(G74ClientPmic(&pm));Cases++;
 for(unsigned field=0;field<10;field++){r=original;((uint32_t*)&r.Status)[field]^=1;assert(!Complete(&r));Cases++;}
 r=original;r.Status.RegisterCount=49;assert(!Complete(&r));Cases++;
 for(unsigned i=0;i<16;i++){r=original;r.Status.BuildId[i]^=1;assert(!Complete(&r));Cases++;}
 for(unsigned i=0;i<4;i++){r=original;(&r.Status.RunAttempts)[i]^=1;assert(!Complete(&r));Cases++;}
 for(unsigned i=0;i<50;i++){
  r=original;r.Before[i]^=1;if(i==12&&r.Before[i]==7)r.Before[i]=1;assert(!Complete(&r));
  r=original;r.After[i]^=1;assert(!Complete(&r));Cases+=2;
 }
 for(unsigned i=0;i<14;i++){r=original;((uint32_t*)&r.Off)[i]^=1;assert(!Complete(&r));Cases++;}
 for(unsigned i=0;i<6;i++){r=original;((uint32_t*)r.Off.ClientBefore)[i]^=1;assert(!Complete(&r));Cases++;}
 r=original;r.Off.AckRaw^=1;assert(!Complete(&r));r=original;r.Off.NoAckRaw=1;assert(!Complete(&r));r=original;r.Off.LastOffWriteTxn=5;assert(!Complete(&r));r=original;r.Off.LastOffObserveTxn=9;assert(!Complete(&r));Cases+=4;
 for(unsigned i=0;i<16;i++){r=original;((uint32_t*)r.Off.GuardBefore)[i]^=1;assert(!Complete(&r));Cases++;}
 for(unsigned i=0;i<3;i++){
  r=original;r.Off.Pmic[i].Status^=1;assert(!Complete(&r));
  for(unsigned j=0;j<r.Off.Pmic[i].TraceCount;j++)if(original.Off.Pmic[i].Trace[j].Kind==2){r=original;r.Off.Pmic[i].Trace[j].Value^=1;assert(!Complete(&r));Cases++;}
  r=original;r.Off.Pmic[i].Trace[r.Off.Pmic[i].TraceCount].Kind=1;assert(!Complete(&r));Cases+=2;
 }
 for(unsigned i=0;i<10;i++){
  for(unsigned j=0;j<14;j++){
   r=original;((uint32_t*)&r.Off.Transactions[i])[j]^=j==10?0x10000u:1u;assert(!Complete(&r));Cases++;
  }
  for(unsigned j=0;j<original.Off.Transactions[i].TraceCount;j++)if(original.Off.Transactions[i].Trace[j].Kind==2){r=original;r.Off.Transactions[i].Trace[j].Value^=1;assert(!Complete(&r));r=original;r.Off.Transactions[i].Trace[j].Address^=4;assert(!Complete(&r));Cases+=2;}
  r=original;r.Off.Transactions[i].Trace[r.Off.Transactions[i].TraceCount].Kind=1;assert(!Complete(&r));Cases++;
 }
 r=original;r.Off.Transactions[10].Code=1;assert(!Complete(&r));Cases++;
 r=original;r.Nonce=41;assert(!Complete(&r));r=original;r.Attempt=2;assert(!Complete(&r));r=original;r.BaselineValid=0;assert(!Complete(&r));r=original;r.FixedRegistersUnchanged=0;assert(!Complete(&r));r=original;r.Reserved=1;assert(!Complete(&r));r=original;r.CounterFrequency++;assert(!Complete(&r));Cases+=6;
 ready.MapCalls=0;assert(!G74ClientReady(&ready));ready.MapCalls=18;ready.ObserverCaptures=2;assert(!G74ClientReady(&ready));ready.ObserverCaptures=1;ready.ObserverFault=1;assert(!G74ClientReady(&ready));Cases+=3;
 const char*good[]={"x.exe status 0000000000000000000000000000002a","\"X:\\path with spaces\\x.exe\" run 0000000000000000000000000000002a","x.exe  result  0000000000000000000000000000002a","x.exe absent 0123456789abcdef0123456789abcdef","x.exe pmic 0123456789abcdef0123456789abcdef","x.exe snapshot 0123456789abcdef0123456789abcdef"};
 for(unsigned i=0;i<6;i++){assert(Parse(good[i]));Cases++;}
 const char*bad[]={"","x.exe","x.exe run","x.exe r 0000000000000000000000000000002a","x.exe run 0000000000000000000000000000002A","x.exe run 00000000000000000000000000000000","x.exe run ffffffffffffffff0000000000000000","x.exe run 0000000000000000000000000000002a extra","x.exe run 0000000000000000000000000000002a ","x.exe run 000000000000000000000000000002a","x.exe run 00000000000000000000000000000002a","x.exe run \"0000000000000000000000000000002a\"","\"\" run 0000000000000000000000000000002a","x\".exe run 0000000000000000000000000000002a"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){assert(!Parse(bad[i]));Cases++;}
 assert(!G74ClientRun(NULL,Expected,42)&&!G74ClientRun(&original,NULL,42)&&!G74ClientRun(&original,Expected,0));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"fixture_is_native\":false,\"packet_bytes\":44728,\"native_operations\":0}\n",Cases);return 0;
}
