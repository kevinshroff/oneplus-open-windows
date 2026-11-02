/* SPDX-License-Identifier: MIT */
#include "g54_lifecycle.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned Pop(unsigned x){unsigned n=0;for(;x;x>>=1)n+=x&1;return n;}
static void Sum(uint8_t*b,unsigned n){unsigned sum=0;for(unsigned i=0;i<n-2;i++)sum+=b[i];b[n-2]=(uint8_t)sum;b[n-1]=(uint8_t)(sum>>8);}
static unsigned Raw(uint8_t*b,unsigned mask,unsigned x,unsigned y){unsigned n=0;memset(b,0,90);b[0]=0x80;for(unsigned id=0;id<10;id++)if(mask&(1u<<id)){uint8_t*p=b+8+n++*8;p[0]=(uint8_t)((id<<4)|2);p[2]=(uint8_t)x;p[3]=(uint8_t)(x>>8);p[4]=(uint8_t)y;p[5]=(uint8_t)(y>>8);p[6]=p[7]=12;}b[2]=(uint8_t)n;Sum(b,8);Sum(b+8,n*8+2);return 8+n*8+2;}
static unsigned Le16(const uint8_t*b){return(unsigned)b[0]|((unsigned)b[1]<<8);}
int main(void){G54_STATE s,before;G54_PLAN p;uint8_t raw[90];unsigned cases=0,n;
 for(unsigned previous=0;previous<1024;previous++)for(unsigned current=0;current<1024;current++){
  memset(&s,0,sizeof(s));s.Mask=previous;s.Generation=7;for(unsigned id=0;id<10;id++){s.Last[id].X=100+id;s.Last[id].Y=200+id;}
  before=s;n=Raw(raw,current,11340,12200);assert(G54Prepare(&s,raw,n,65535,&p)&&!p.Error&&!memcmp(&s,&before,sizeof(s)));unsigned all=previous|current;
  assert(p.HaveReport==(all!=0));
  if(all){assert(p.Report[0]==1&&p.Report[63]==Pop(all)&&Le16(p.Report+61)==65535);unsigned slot=0;
   for(unsigned id=0;id<10;id++)if(all&(1u<<id)){const uint8_t*q=p.Report+1+slot++*6;assert(q[1]==id);if(current&(1u<<id)){assert(q[0]==3&&Le16(q+2)==11340&&Le16(q+4)==12200);}else assert(q[0]==2&&Le16(q+2)==100+id&&Le16(q+4)==200+id);}
   assert(G54Commit(&s,&p)&&s.Mask==current&&s.Generation==8);assert(!G54Commit(&s,&p));
  }else assert(!G54Commit(&s,&p));cases++;
 }
 const unsigned corners[5][4]={{0,0,0,24400},{22680,0,0,0},{0,24400,22680,24400},{22680,24400,22680,0},{11340,12200,11340,12200}};
 for(unsigned i=0;i<5;i++){memset(&s,0,sizeof(s));n=Raw(raw,1,corners[i][0],corners[i][1]);assert(G54Prepare(&s,raw,n,0,&p)&&p.HaveReport&&Le16(p.Report+3)==corners[i][2]&&Le16(p.Report+5)==corners[i][3]);cases++;}
 memset(&s,0,sizeof(s));n=Raw(raw,1,11340,12200);assert(G54Prepare(&s,raw,n,0xffff,&p));before=s;assert(!memcmp(&s,&before,sizeof(s)));assert(G54Commit(&s,&p));n=Raw(raw,1,0,24400);assert(G54Prepare(&s,raw,n,0,&p)&&G54Commit(&s,&p));n=Raw(raw,0,0,0);assert(G54Prepare(&s,raw,n,1,&p)&&p.Report[63]==1&&p.Report[1]==2&&Le16(p.Report+3)==22680&&Le16(p.Report+5)==24400&&G54Commit(&s,&p)&&!s.Mask);cases++;
 s.Mask=1023;for(unsigned i=0;i<10;i++){s.Last[i].X=100+i;s.Last[i].Y=200+i;}assert(G54ReleaseAll(&s,2,&p)&&p.Report[63]==10);for(unsigned i=0;i<10;i++)assert(p.Report[1+i*6]==2&&Le16(p.Report+3+i*6)==100+i);assert(G54Commit(&s,&p)&&!s.Mask);cases++;
 memset(&s,0,sizeof(s));s.Generation=0xffffffffu;n=Raw(raw,1,0,0);assert(G54Prepare(&s,raw,n,0,&p)&&G54Commit(&s,&p)&&s.Generation==0);cases++;
 for(unsigned mode=0;mode<6;mode++){memset(&s,0,sizeof(s));n=Raw(raw,1,11340,12200);if(mode==0)raw[6]^=1;if(mode==1)raw[16]^=1;if(mode==2){raw[8]=5;Sum(raw+8,10);}if(mode==3){raw[0]=0x88;Sum(raw,8);}if(mode==4)n=Raw(raw,1,22681,0);if(mode==5){raw[2]=11;Sum(raw,8);}assert(!G54Prepare(&s,raw,n,0,&p)&&p.Error);cases++;}
 memset(&s,0,sizeof(s));s.Mask=1;s.Last[0].X=5;s.Last[0].Y=6;before=s;memset(raw,0,8);assert(G54Prepare(&s,raw,8,0,&p)&&!p.HaveReport&&!memcmp(&s,&before,sizeof(s)));cases++;
 assert(!G54ReleaseAll(0,0,&p)&&p.Error);assert(!G54Prepare(0,raw,8,0,&p)&&p.Error);assert(!G54Commit(0,&p));assert(!G54Commit(&s,0));assert(!G54ReleaseAll(&s,0,0));cases+=5;
 memset(&s,0,sizeof(s));n=Raw(raw,3,11340,12200);raw[16]=2;Sum(raw+8,18);assert(!G54Prepare(&s,raw,n,0,&p)&&p.Error);cases++;
 memset(&s,0,sizeof(s));s.Mask=1;s.Last[0].X=123;s.Last[0].Y=456;memcpy(raw,(uint8_t[]){0x80,3,0,0,0,3,0x86,0,255,255},10);assert(G54Prepare(&s,raw,26,3,&p)&&p.HaveReport&&p.Report[63]==1&&p.Report[1]==2&&Le16(p.Report+3)==123&&Le16(p.Report+5)==456&&G54Commit(&s,&p)&&!s.Mask);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"all1024_previous_and_current_contact_masks\":true,\"UP_retains_ID_position_confidence_and_report_count\":true,\"prepare_does_not_mutate_accepted_state\":true,\"stale_double_commit_refused\":true,\"axis_endpoint_and_scan_wrap_cases\":true,\"invalid_or_unqualified_raw_data_refused\":true}\n",cases);return 0;}
