#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "query_protocol.h"
static void start(G1268_REPORT *r){G1268Initialize(r);assert(r->State==G1268_IDLE&&r->Flags==0&&r->QueriesAccepted==0);assert(r->Input[0]==0xc2000601ULL&&r->Input[1]==1&&r->Input[2]==0x02000c1bULL);assert(G1268Accept(r));assert(!G1268Accept(r));assert(G1268Begin(r));assert(!G1268Begin(r));}
static G1268_REPORT finish(G1268_U64 status,G1268_U64 primary){G1268_REPORT r;start(&r);G1268_MONITOR_FRAME f={{0},1,1,0};f.X[0]=status;f.X[1]=primary;f.X[6]=0xa6a6;G1268Finish(&r,&f);assert(r.Monitor.X[0]==status&&r.Monitor.X[6]==0xa6a6);assert(!G1268Accept(&r));return r;}
int main(void){G1268_REPORT r=finish(0,1);assert(r.State==G1268_COMPLETE&&r.Availability==G1268_CAP_AVAILABLE);r=finish(0,0);assert(r.State==G1268_COMPLETE&&r.Availability==G1268_CAP_UNAVAILABLE);
 r=finish(0xfffffffffffffff4ULL,1);assert(r.State==G1268_ERROR&&(r.Flags&G1268_F_BUSY)&&r.Availability==G1268_CAP_UNKNOWN);
 r=finish(0xffffffffffffffffULL,1);assert(r.State==G1268_ERROR&&(r.Flags&G1268_F_UNSUPPORTED)&&r.Availability==G1268_CAP_UNKNOWN);
 r=finish(0xfffffffffffffffcULL,1);assert(r.State==G1268_ERROR&&(r.Flags&G1268_F_UNSUPPORTED));
 r=finish(0xfffffffffffffff9ULL,1);assert(r.State==G1268_ERROR&&!(r.Flags&G1268_F_COMPLETION));
 for(unsigned int i=1;i<=4;i++){r=finish(i,1);assert(r.State==G1268_INCOMPLETE_RETAINED&&(r.Flags&G1268_F_RETAINED)&&r.Availability==G1268_CAP_UNKNOWN);}
 start(&r);G1268_MONITOR_FRAME f={{0},3,3,2};f.X[1]=1;G1268Finish(&r,&f);assert(r.State==G1268_COMPLETE&&r.Monitor.Interrupted==2);
 for(unsigned int i=0;i<3;i++){start(&r);f=(G1268_MONITOR_FRAME){{0},1,1,0};if(i==0)f.Returns=0;if(i==1)f.Entries=2;if(i==2)f.Interrupted=1;G1268Finish(&r,&f);assert(r.State==G1268_INCOMPLETE_RETAINED&&r.Availability==0);}
 r=finish(0x100000000ULL,1);assert(r.State==G1268_INCOMPLETE_RETAINED&&r.Availability==0);r=finish(0x100000001ULL,1);assert(r.State==G1268_INCOMPLETE_RETAINED&&r.Availability==0);
 for(unsigned int i=0;i<4;i++){const G1268_U64 e[]={0xfffffff4ULL,0xffffffffULL,0xfffffffcULL,0xfffffff9ULL};r=finish(e[i],1);assert(r.State==G1268_ERROR&&r.Availability==0&&!(r.Flags&G1268_F_RETAINED));if(i==0)assert(r.Flags&G1268_F_BUSY);if(i==1||i==2)assert(r.Flags&G1268_F_UNSUPPORTED);}
 for(unsigned int i=0;i<4;i++){const G1268_U64 e[]={0x00000001fffffff4ULL,0xfffffffeffffffffULL,0x8000000000000000ULL,0xffffffff00000001ULL};r=finish(e[i],1);assert(r.State==G1268_INCOMPLETE_RETAINED&&r.Availability==0&&!(r.Flags&(G1268_F_BUSY|G1268_F_UNSUPPORTED|G1268_F_COMPLETION)));}
 printf("production state core: 24 completion/interrupt/error/retain/once cases PASS; monitor calls0\n");return 0;}
