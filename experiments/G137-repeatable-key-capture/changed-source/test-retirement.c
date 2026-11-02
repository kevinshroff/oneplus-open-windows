/* SPDX-License-Identifier: MIT */
#include "g137_capture.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned Cases;
static G137_LEDGER L;
static unsigned char *Frozen,*Echo;
static void Reset(void){G137CaptureInit(&L);for(unsigned i=0;i<G137_CAPTURE_BYTES;i++)Frozen[i]=(unsigned char)(i*37u+11u);memcpy(Echo,Frozen,G137_CAPTURE_BYTES);}
static void Ready(uint64_t nonce){assert(G137CaptureBegin(&L,nonce));assert(G137CaptureComplete(&L,5,1));assert(L.Phase==G137_READY);}
int main(void)
{
 Frozen=malloc(G137_CAPTURE_BYTES);Echo=malloc(G137_CAPTURE_BYTES);assert(Frozen&&Echo);
 Reset();G137_STATE out;memset(&out,0xcc,sizeof(out));G137CaptureState(&L,&out);
 assert(out.Size==64&&out.Version==1&&out.Magic==G137_STATE_MAGIC&&!out.Phase&&!out.Captures&&!out.Retirements&&!out.Reserved&&out.Slots==32);Cases++;
 assert(!G137CaptureBegin(&L,0)&&!G137CaptureBegin(NULL,1)&&!G137CaptureCanBegin(NULL,1));Cases++;
 assert(!G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES));Cases++;
 Ready(1);assert(!G137CaptureBegin(&L,2));Cases++;
 for(unsigned n=0;n<24;n++){
  unsigned at=n<8?n:n<16?G137_CAPTURE_BYTES-1-(n-8):(n-16)*4093+97;
  Echo[at]^=1;G137_LEDGER before=L;assert(!G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES));assert(!memcmp(&L,&before,sizeof(L)));Echo[at]^=1;Cases++;
 }
 for(unsigned n=0;n<6;n++){
  const uint32_t sizes[]={0,1,G137_CAPTURE_BYTES-1,G137_CAPTURE_BYTES+1,0xffffffffu,64};
  assert(!G137CaptureRetire(&L,1,Frozen,Echo,sizes[n]));assert(L.Phase==G137_READY&&!L.Retired);Cases++;
 }
 assert(!G137CaptureRetire(&L,0,Frozen,Echo,G137_CAPTURE_BYTES)&&!G137CaptureRetire(&L,2,Frozen,Echo,G137_CAPTURE_BYTES));Cases++;
 assert(!G137CaptureRetire(&L,1,NULL,Echo,G137_CAPTURE_BYTES)&&!G137CaptureRetire(&L,1,Frozen,NULL,G137_CAPTURE_BYTES));Cases++;
 assert(G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES)==1&&L.Phase==G137_EMPTY&&L.Retired==1&&L.TotalMaps==5);Cases++;
 G137_LEDGER before=L;assert(G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES)==2&&!memcmp(&before,&L,sizeof(L)));Cases++;
 Echo[123]^=1;assert(!G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES));Echo[123]^=1;Cases++;
 assert(!G137CaptureBegin(&L,1));Cases++;
 assert(G137CaptureBegin(&L,2));assert(!G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES));Cases++;
 assert(G137CaptureComplete(&L,5,1));assert(!G137CaptureRetire(&L,1,Frozen,Echo,G137_CAPTURE_BYTES));Cases++;
 assert(G137CaptureRetire(&L,2,Frozen,Echo,G137_CAPTURE_BYTES)==1);Cases++;
 Reset();
 for(uint64_t n=1;n<=G137_CAPTURE_SLOTS;n++){
  Ready(n);assert(G137CaptureRetire(&L,n,Frozen,Echo,G137_CAPTURE_BYTES)==1);assert(L.Count==n&&L.Retired==n&&L.TotalMaps==n*5);Cases++;
 }
 assert(!G137CaptureBegin(&L,33)&&L.Phase==G137_EMPTY&&L.Count==32);Cases++;
 for(unsigned maps=0;maps<=5;maps++){
  Reset();assert(G137CaptureBegin(&L,3));assert(G137CaptureComplete(&L,maps,0));assert(L.Phase==G137_FAULT);before=L;
  assert(!G137CaptureRetire(&L,3,Frozen,Echo,G137_CAPTURE_BYTES)&&!G137CaptureBegin(&L,4)&&!memcmp(&before,&L,sizeof(L)));Cases++;
 }
 for(unsigned maps=0;maps<5;maps++){
  Reset();assert(G137CaptureBegin(&L,1));assert(!G137CaptureComplete(&L,maps,1)&&L.Phase==G137_FAULT);Cases++;
 }
 Reset();assert(!G137CaptureComplete(&L,5,1)&&L.Phase==G137_FAULT);Cases++;
 Reset();assert(G137CaptureBegin(&L,1));assert(!G137CaptureComplete(&L,6,0)&&L.Phase==G137_FAULT);Cases++;
 Reset();L.TotalMaps=5;assert(!G137CaptureBegin(&L,1));Cases++;
 Reset();Ready(9);L.Used[0]=8;assert(!G137CaptureRetire(&L,9,Frozen,Echo,G137_CAPTURE_BYTES));Cases++;
 Reset();Ready(9);L.TotalMaps=6;assert(!G137CaptureRetire(&L,9,Frozen,Echo,G137_CAPTURE_BYTES));Cases++;
 Reset();assert(G137CaptureBegin(&L,1));L.Used[0]=2;assert(!G137CaptureComplete(&L,5,1)&&L.Phase==G137_FAULT);Cases++;
 G137CaptureInit(NULL);G137CaptureState(NULL,&out);G137CaptureState(&L,NULL);assert(!G137CaptureComplete(NULL,0,0));Cases++;
 free(Frozen);free(Echo);
 printf("{\"passed\":true,\"cases\":%u,\"actual_portable_lifecycle_C\":true,\"native_operations\":0}\n",Cases);return 0;
}
