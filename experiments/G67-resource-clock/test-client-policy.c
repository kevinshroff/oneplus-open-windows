/* SPDX-License-Identifier: MIT -- capture fixture is modeled, never native. */
#include "g67_client_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned Cases;
static int Parse(const char*s){uint16_t command[256];char nonce[33];uint64_t value=0;uint32_t cycle;size_t n=strlen(s);assert(n<256);for(size_t i=0;i<=n;i++)command[i]=(uint8_t)s[i];return G67ClientParse(command,&cycle,nonce,&value);}
int main(int argc,char**argv)
{
 assert(argc==2);FILE*f=fopen(argv[1],"rb");G67_REPORT original,r;assert(f&&fread(&original,1,sizeof(original),f)==sizeof(original)&&fgetc(f)==EOF&&!fclose(f));
 assert(G67ClientReportShape(&original,742)&&G67ClientCycleComplete(&original,742,42)&&!G67ClientReadyForCycle(&original,742));Cases++;
 r=original;r.CycleAttempts=0;memset(&r.Clock,0,sizeof(r.Clock));assert(G67ClientReadyForCycle(&r,742)&&!G67ClientCycleComplete(&r,742,42));Cases++;
 for(unsigned word=0;word<22;word++){r=original;((uint32_t*)&r)[word]^=1;assert(!G67ClientCycleComplete(&r,742,42));Cases++;}
 for(unsigned row=0;row<3;row++)for(unsigned side=0;side<2;side++){r=original;(side?r.Translated:r.Raw)[row][0]^=1;assert(!G67ClientCycleComplete(&r,742,42));Cases++;}
 for(unsigned field=0;field<10;field++){
  r=original;uint32_t*fields=&r.Clock.Code;fields[field]^=1;assert(!G67ClientCycleComplete(&r,742,42));Cases++;
 }
 for(unsigned row=0;row<6;row++){r=original;r.Clock.Before[row]^=1;assert(!G67ClientCycleComplete(&r,742,42));r=original;r.Clock.After[row]^=1;assert(!G67ClientCycleComplete(&r,742,42));Cases+=2;}
 for(unsigned row=0;row<r.Clock.TraceCount;row++){
  if(original.Clock.Trace[row].Kind==2){r=original;r.Clock.Trace[row].Value^=1;assert(!G67ClientCycleComplete(&r,742,42));Cases++;}
 }
 r=original;r.Clock.Trace[original.Clock.TraceCount].Kind=1;assert(!G67ClientCycleComplete(&r,742,42));Cases++;
 assert(!G67ClientCycleComplete(&original,576,42)&&!G67ClientCycleComplete(&original,742,41)&&!G67ClientCycleComplete(NULL,742,42));Cases++;
 const char*good[]={"x.exe query 0123456789abcdef0123456789abcdef","\"X:\\path with space\\g67.exe\" cycle 0123456789abcdef0123456789abcdef","x.exe   query   0000000000000000000000000000002a"};
 for(unsigned i=0;i<sizeof(good)/sizeof(good[0]);i++){assert(Parse(good[i]));Cases++;}
 const char*bad[]={"","x.exe","x.exe query","x.exe decode 0123456789abcdef0123456789abcdef","x.exe query 0123456789ABCDEF0123456789ABCDEF","x.exe query 0123456789abcdef0123456789abcde","x.exe query 0123456789abcdef0123456789abcdef0","x.exe query 0123456789abcdef0123456789abcdef extra","x.exe query 0123456789abcdef0123456789abcdef ","x.exe query 00000000000000000000000000000000","x.exe query ffffffffffffffff0000000000000000","\"\" query 0123456789abcdef0123456789abcdef","\"x.exe query 0123456789abcdef0123456789abcdef","x\".exe query 0123456789abcdef0123456789abcdef"," x.exe query 0123456789abcdef0123456789abcdef","x.exe query \"0123456789abcdef0123456789abcdef\""};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){assert(!Parse(bad[i]));Cases++;}
 printf("{\"passed\":true,\"cases\":%u,\"packet_bytes\":%zu,\"fixture_is_native\":false,\"native_operations\":0}\n",Cases,sizeof(original));return 0;
}
