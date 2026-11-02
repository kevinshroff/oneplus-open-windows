/* SPDX-License-Identifier: MIT */
#include "g54_poll.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "poll-input.h"
typedef struct{uint64_t Now,LastClock;unsigned Reads,Clears,PhysicalClears,Quiets,Waits,Clocks,Mode,At;}Model;
static void Sum(uint8_t*b,unsigned n){unsigned sum=0;for(unsigned i=0;i<n-2;i++)sum+=b[i];b[n-2]=(uint8_t)sum;b[n-1]=(uint8_t)(sum>>8);}
static int Read(void*c,uint32_t at,uint8_t*out,uint32_t n){Model*m=c;assert(at==G54_TOUCH_ADDRESS&&n==26);m->Reads++;m->Now+=1000;if(m->Mode==1&&m->Reads==m->At)return 0;memcpy(out,Contact,26);if(m->Mode==2&&m->Reads==m->At)return 0;if(m->Mode==20){out[0]=0x40;out[2]=1;Sum(out,8);}if(m->Mode==21)out[16]^=1;if(m->Mode==22)memset(out,0,26);return 1;}
static int Clear(void*c){Model*m=c;m->Clears++;m->Now+=1000;if(m->Mode==3&&m->Clears==m->At)return 0;m->PhysicalClears++;return !(m->Mode==4&&m->Clears==m->At);}
static int Quiet(void*c){Model*m=c;m->Quiets++;if(m->Mode==10&&m->Quiets==18)m->Now+=300000;return !(m->Mode==5&&m->Quiets==m->At);}
static void Wait(void*c){Model*m=c;m->Waits++;m->Now+=10000;}
static uint64_t Clock(void*c){Model*m=c;unsigned i=m->Clocks++;uint64_t value=m->Now;if(m->Mode==6&&i==m->At)value=m->LastClock-1;if(m->Mode==7&&i==m->At)value=1250001;m->LastClock=value;return value;}
static int Run(unsigned mode,unsigned at,Model*out,G54_POLL_RESULT*r){Model m={0};G54_POLL_IO io={&m,Read,Clear,Quiet,Wait,Clock};m.Now=1000000;m.Mode=mode;m.At=at;int ok=G54Poll(&io,r);assert(m.Reads<=8&&m.Clears<=8&&m.Waits<=7&&m.Quiets<=18&&m.Clocks<=26);if(out)*out=m;return ok;}
int main(void){G54_POLL_RESULT r;Model m;unsigned cases=0;assert(Run(0,0,&m,&r));assert(r.Cycles==8&&r.ReadAttempts==8&&r.ClearAttempts==8&&r.ClearCompleted==8&&r.ContactRecords==8&&r.BusQuiescent);cases++;
 for(unsigned mode=1;mode<=4;mode++)for(unsigned at=1;at<=8;at++){assert(!Run(mode,at,&m,&r));assert(r.BusQuiescent);if(mode<=2)assert(m.Reads==at&&m.Clears==at-1&&r.Code==G54_POLL_READ);else assert(m.Clears==at&&r.ClearCompleted==at-1&&r.Code==G54_POLL_CLEAR);cases++;}
 for(unsigned at=1;at<=18;at++){assert(!Run(5,at,&m,&r)&&!r.BusQuiescent&&r.Code==G54_POLL_QUIET);cases++;}
 for(unsigned mode=6;mode<=7;mode++)for(unsigned at=1;at<=25;at++){assert(!Run(mode,at,&m,&r)&&r.Code==G54_POLL_CLOCK&&r.BusQuiescent);cases++;}
 assert(!Run(10,0,&m,&r)&&r.Code==G54_POLL_CLOCK&&r.BusQuiescent);cases++;
 for(unsigned mode=20;mode<=21;mode++){assert(!Run(mode,0,&m,&r)&&r.Code==G54_POLL_DECODE&&!m.Clears&&r.BusQuiescent);cases++;}
 assert(Run(22,0,&m,&r)&&r.IdleRecords==8&&!m.Clears);cases++;
 G54_POLL_IO io={0};assert(!G54Poll(0,&r)&&r.Code==G54_POLL_ARGUMENT);assert(!G54Poll(&io,&r)&&r.Code==G54_POLL_ARGUMENT);assert(!G54Poll(&io,0));cases+=3;
 printf("{\"passed\":true,\"cases\":%u,\"all_read_clear_quiet_clock_boundaries\":true,\"failed_clear_not_retried\":true,\"unknown_request_and_bad_checksum_not_cleared\":true,\"final_quiet_in_deadline\":true}\n",cases);return 0;}
