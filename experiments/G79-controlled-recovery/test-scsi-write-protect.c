#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef size_t UINTN;
typedef intptr_t INTN;
#define STATIC static
#define CONST const
#include "OpenScsiWriteProtect.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"failed line %d\n",__LINE__);exit(1); } } while (0)
int main(void) {
  UINT8 good[31]={'U','S','B','C'}, cbw[31], data[8], before[8];
  good[8]=192;good[12]=0x80;good[14]=6;good[15]=0x1a;good[19]=192;
  for(unsigned lun=0;lun<2;lun++) {
    memcpy(cbw,good,31);cbw[13]=lun;
    UINT8 header[4]={3,0,0,0};
    CHECK(OpenProtectModeSense6(cbw,31,header,4)==1);
    CHECK(header[0]==3 && header[1]==0 && header[2]==0x80 && header[3]==0);
    CHECK(OpenProtectModeSense6(cbw,31,header,4)==1);
    CHECK(memcmp(cbw,good,13)==0 && cbw[13]==lun && memcmp(cbw+14,good+14,17)==0);
  }
  for(unsigned op=0;op<256;op++) {
    if(op==0x1a)continue;
    memcpy(cbw,good,31);cbw[15]=op;memset(data,0xa5,sizeof data);memcpy(before,data,sizeof data);
    CHECK(OpenProtectModeSense6(cbw,31,data,4)==0);CHECK(memcmp(data,before,sizeof data)==0);
  }
  // Short CBWs cannot be inspected out of bounds or mutate output.
  for(unsigned n=0;n<31;n++) {
    UINT8 *shortcbw=malloc(n?n:1);if(n)memcpy(shortcbw,good,n);
    memset(data,0xa5,sizeof data);memcpy(before,data,sizeof data);
    CHECK(OpenProtectModeSense6(shortcbw,n,data,4)==0);CHECK(memcmp(data,before,sizeof data)==0);free(shortcbw);
  }
  for(unsigned n=0;n<8;n++) {
    if(n==4)continue;memcpy(cbw,good,31);memset(data,0xa5,sizeof data);memcpy(before,data,sizeof data);
    CHECK(OpenProtectModeSense6(cbw,31,data,n)==-1);CHECK(memcmp(data,before,sizeof data)==0);
  }
  // Malformed matching commands and unexpected payloads fail without edits.
  const unsigned fields[]={8,9,12,13,14,19};
  for(unsigned k=0;k<sizeof(fields)/sizeof(fields[0]);k++)for(unsigned value=0;value<256;value++) {
    memcpy(cbw,good,31);cbw[fields[k]]=value;memset(data,0,sizeof data);data[0]=3;memcpy(before,data,sizeof data);
    INTN r=OpenProtectModeSense6(cbw,31,data,4);
    CHECK(r==1 || r==-1);
    if(r==1){CHECK(data[2]==0x80 && data[0]==3 && data[1]==0 && data[3]==0);}
    else {CHECK(memcmp(data,before,sizeof data)==0);}
    CHECK(memcmp(data+4,before+4,4)==0);
  }
  for(unsigned field=0;field<4;field++)for(unsigned value=0;value<256;value++) {
    memcpy(cbw,good,31);memset(data,0,sizeof data);data[0]=3;data[field]=value;memcpy(before,data,sizeof data);
    INTN r=OpenProtectModeSense6(cbw,31,data,4);
    if(r==-1){CHECK(memcmp(data,before,sizeof data)==0);}else {CHECK(r==1 && data[2]==0x80);}
  }
  CHECK(OpenProtectModeSense6(NULL,31,data,4)==0);
  CHECK(OpenProtectModeSense6(good,31,NULL,4)==-1);
  printf("PASS %u SCSI write-protection checks; only header byte 2 may change\n",checks);
  return 0;
}
