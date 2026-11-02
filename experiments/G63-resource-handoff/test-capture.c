/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "g63_capture.h"
static unsigned Cases;
typedef struct {unsigned char Before[16];G63_REPORT Report;unsigned char After[16];}Guard;
static Guard New(void){Guard g;memset(&g,0,sizeof(g));memset(g.Before,0x56,16);memset(g.After,0xa9,16);g.Report.Size=sizeof(g.Report);g.Report.Version=1;g.Report.Magic=G63_MAGIC;g.Report.KernelBuild=26100;g.Report.Processors=8;return g;}
static void Check(const Guard*g){for(unsigned i=0;i<16;i++)assert(g->Before[i]==0x56&&g->After[i]==0xa9);assert(g->Report.Size==608&&g->Report.Version==1&&g->Report.Magic==G63_MAGIC&&g->Report.KernelBuild==26100&&g->Report.Processors==8);}
static void U16(unsigned char*p,unsigned n){p[0]=(unsigned char)n;p[1]=(unsigned char)(n>>8);}
static void U32(unsigned char*p,unsigned n){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(i*8));}
static void U64(unsigned char*p,unsigned long long n){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(i*8));}
int main(int argc,char**argv){assert(argc==2);unsigned char src[12][32],translated[12][32];for(unsigned i=0;i<12;i++)for(unsigned j=0;j<32;j++){src[i][j]=(unsigned char)(i*33+j+1);translated[i][j]=(unsigned char)(src[i][j]^0x80);}
 for(unsigned raw=0;raw<=9;raw++)for(unsigned tr=0;tr<=9;tr++)for(unsigned bytes=0;bytes<=34;bytes++){
  Guard g=New();G63_REPORT*r=&g.Report;G63CaptureBegin(r,raw,tr,bytes);for(unsigned i=0;i<12;i++){G63CaptureRow(r,0,i,src[i]);G63CaptureRow(r,1,i,translated[i]);}G63CaptureEnd(r);Check(&g);
  unsigned sr=(bytes&&bytes<=32)?(raw<8?raw:8):0,st=(bytes&&bytes<=32)?(tr<8?tr:8):0;unsigned flags=(raw>8?G63_RAW_CAP:0)|(tr>8?G63_TRANSLATED_CAP:0)|(!bytes||bytes>32?G63_DESCRIPTOR_SIZE:0)|(raw!=tr?G63_COUNT_MISMATCH:0)|(sr!=raw?G63_RAW_MISSING:0)|(st!=tr?G63_TRANSLATED_MISSING:0);
  assert(r->PrepareCalls==1&&r->RawCount==raw&&r->TranslatedCount==tr&&r->StoredRaw==sr&&r->StoredTranslated==st&&r->DescriptorBytes==bytes&&r->CaptureFlags==flags&&r->CaptureComplete==(flags==0));
  for(unsigned i=0;i<8;i++)for(unsigned j=0;j<32;j++){assert(r->Raw[i][j]==(i<sr&&j<bytes?src[i][j]:0));assert(r->Translated[i][j]==(i<st&&j<bytes?translated[i][j]:0));}Cases++;
 }
 for(int tr=0;tr<2;tr++)for(unsigned missing=0;missing<2;missing++){
  Guard g=New();G63CaptureBegin(&g.Report,2,2,20);for(unsigned i=0;i<2;i++){G63CaptureRow(&g.Report,0,i,!tr&&i==missing?NULL:src[i]);G63CaptureRow(&g.Report,1,i,tr&&i==missing?NULL:translated[i]);}G63CaptureEnd(&g.Report);Check(&g);assert(!g.Report.CaptureComplete&&g.Report.CaptureFlags==(tr?G63_TRANSLATED_MISSING:G63_RAW_MISSING));Cases++;
 }
 Guard g=New();G63CaptureBegin(&g.Report,2,2,20);G63CaptureRow(&g.Report,0,1,src[1]);G63CaptureRow(&g.Report,0,0,src[0]);G63CaptureRow(&g.Report,0,1,src[1]);for(unsigned i=0;i<2;i++)G63CaptureRow(&g.Report,1,i,translated[i]);G63CaptureEnd(&g.Report);assert(!g.Report.CaptureComplete&&g.Report.CaptureFlags==G63_RAW_MISSING);Check(&g);Cases++;
 G63CaptureBegin(&g.Report,2,2,20);for(unsigned i=0;i<2;i++){G63CaptureRow(&g.Report,0,i,src[i]);G63CaptureRow(&g.Report,1,i,translated[i]);}G63CaptureEnd(&g.Report);assert(g.Report.CaptureComplete&&g.Report.PrepareCalls==2);Check(&g);Cases++;
 /* Independent C fixture: raw and translated interrupt numbers differ. */
 g=New();g.Report.FirmwareBytes=730;g.Report.FirmwareMatch=1;g.Report.D0Entries=g.Report.InD0=1;memset(src,0,sizeof(src));memset(translated,0,sizeof(translated));src[0][0]=3;src[0][1]=1;U64(src[0]+4,0xa90000);U32(src[0]+12,0x4000);memcpy(translated[0],src[0],20);src[1][0]=2;src[1][1]=1;U16(src[1]+4,389);U32(src[1]+8,389);U64(src[1]+12,~0ull);translated[1][0]=2;translated[1][1]=1;U16(translated[1]+4,6);U32(translated[1]+8,0x2ff);U64(translated[1]+12,0xff);
 G63CaptureBegin(&g.Report,2,2,20);for(unsigned i=0;i<2;i++){G63CaptureRow(&g.Report,0,i,src[i]);G63CaptureRow(&g.Report,1,i,translated[i]);}G63CaptureEnd(&g.Report);Check(&g);assert(g.Report.CaptureComplete);FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&g.Report,1,sizeof(g.Report),f)==sizeof(g.Report)&&!fclose(f));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"report_bytes\":%zu,\"raw_offset\":%zu,\"translated_offset\":%zu,\"fixture_is_a_model_not_native_evidence\":true}\n",Cases,sizeof(G63_REPORT),offsetof(G63_REPORT,Raw),offsetof(G63_REPORT,Translated));return 0;
}
