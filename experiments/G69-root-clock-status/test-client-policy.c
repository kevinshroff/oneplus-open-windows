/* SPDX-License-Identifier: MIT -- capture fixture is modeled, never native. */
#include "g69_client_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned Cases;
static int Parse(const char*s){uint16_t command[256];char nonce[33];uint64_t value=0;uint32_t cycle;size_t n=strlen(s);assert(n<256);for(size_t i=0;i<=n;i++)command[i]=(uint8_t)s[i];return G69ClientParse(command,&cycle,nonce,&value);}
int main(int argc,char**argv)
{
 assert(argc==2);FILE*f=fopen(argv[1],"rb");G69_REPORT original,r;assert(f&&fread(&original,1,sizeof(original),f)==sizeof(original)&&fgetc(f)==EOF&&!fclose(f));
 assert(G69ClientReportShape(&original,742)&&G69ClientCycleComplete(&original,742,42)&&!G69ClientReadyForCycle(&original,742));Cases++;
 r=original;r.CycleAttempts=0;memset(&r.Clock,0,sizeof(r.Clock));assert(G69ClientReadyForCycle(&r,742)&&!G69ClientCycleComplete(&r,742,42));Cases++;
 for(unsigned word=0;word<22;word++){r=original;((uint32_t*)&r)[word]^=1;assert(!G69ClientCycleComplete(&r,742,42));Cases++;}
 for(unsigned row=0;row<3;row++)for(unsigned side=0;side<2;side++){r=original;(side?r.Translated:r.Raw)[row][0]^=1;assert(!G69ClientCycleComplete(&r,742,42));Cases++;}
 for(unsigned field=0;field<10;field++){
  r=original;uint32_t*fields=&r.Clock.Code;fields[field]^=1;assert(!G69ClientCycleComplete(&r,742,42));Cases++;
 }
 for(unsigned row=0;row<6;row++){r=original;r.Clock.Before[row]^=1;assert(!G69ClientCycleComplete(&r,742,42));r=original;r.Clock.After[row]^=1;assert(!G69ClientCycleComplete(&r,742,42));Cases+=2;}
 for(unsigned row=0;row<r.Clock.TraceCount;row++){
  if(original.Clock.Trace[row].Kind==2){r=original;r.Clock.Trace[row].Value^=1;assert(!G69ClientCycleComplete(&r,742,42));Cases++;}
 }
 r=original;r.Clock.Trace[original.Clock.TraceCount].Kind=1;assert(!G69ClientCycleComplete(&r,742,42));Cases++;
 for(unsigned reg=0;reg<4;reg++)for(unsigned bit=0;bit<32;bit++){
  r=original;r.Clock.Enabled[reg]^=1u<<bit;assert(!G69ClientCycleComplete(&r,742,42));Cases++;
 }
 for(unsigned row=0;row<original.Clock.TraceCount;row++){
  r=original;r.Clock.Trace[row].Phase=0x123;assert(!G69ClientCycleComplete(&r,742,42));Cases++;
 }
 r=original;r.Magic=UINT64_C(0x314b4c433736504f);assert(!G69ClientCycleComplete(&r,742,42));Cases++;
 r=original;assert(r.Clock.Reads==35&&r.Clock.TraceCount==41&&r.Clock.Waits==0);
 memmove(&r.Clock.Trace[18],&r.Clock.Trace[15],(r.Clock.TraceCount-15)*sizeof(G69_EVENT));
 r.Clock.Trace[15]=(G69_EVENT){1,1,0x80004000,3};r.Clock.Trace[16]=(G69_EVENT){1,2,0x80000000,3};r.Clock.Trace[17]=(G69_EVENT){3,1,1,3};
 r.Clock.Reads+=2;r.Clock.Waits++;r.Clock.TraceCount+=3;assert(G69ClientCycleComplete(&r,742,42));Cases++;
 assert(!G69ClientCycleComplete(&original,576,42)&&!G69ClientCycleComplete(&original,742,41)&&!G69ClientCycleComplete(NULL,742,42));Cases++;
 const char*good[]={"x.exe query 0123456789abcdef0123456789abcdef","\"X:\\path with space\\g69.exe\" cycle 0123456789abcdef0123456789abcdef","x.exe   query   0000000000000000000000000000002a"};
 for(unsigned i=0;i<sizeof(good)/sizeof(good[0]);i++){assert(Parse(good[i]));Cases++;}
 const char*bad[]={"","x.exe","x.exe query","x.exe decode 0123456789abcdef0123456789abcdef","x.exe query 0123456789ABCDEF0123456789ABCDEF","x.exe query 0123456789abcdef0123456789abcde","x.exe query 0123456789abcdef0123456789abcdef0","x.exe query 0123456789abcdef0123456789abcdef extra","x.exe query 0123456789abcdef0123456789abcdef ","x.exe query 00000000000000000000000000000000","x.exe query ffffffffffffffff0000000000000000","\"\" query 0123456789abcdef0123456789abcdef","\"x.exe query 0123456789abcdef0123456789abcdef","x\".exe query 0123456789abcdef0123456789abcdef"," x.exe query 0123456789abcdef0123456789abcdef","x.exe query \"0123456789abcdef0123456789abcdef\""};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){assert(!Parse(bad[i]));Cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"packet_bytes\":%zu,\"fixture_is_native\":false,\"native_operations\":0}\n",Cases,sizeof(original));return 0;
}
