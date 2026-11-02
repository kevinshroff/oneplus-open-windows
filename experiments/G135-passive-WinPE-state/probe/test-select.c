/* Exercise the actual selection policy; never maps physical memory. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "g135_select.h"
static void put16(uint8_t*p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put32(uint8_t*p,uint32_t v){for(int i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void entry(uint8_t*t,int i,uint32_t off,uint32_t bytes,uint16_t a,uint16_t b){uint8_t*p=t+32+48*i;put32(p,off);put32(p+4,bytes);put16(p+12,a);put16(p+14,b);put32(p+16,64);}
int main(int argc,char**argv){uint8_t toc[4096],original[4096],part[32];G135_PART out[2];uint32_t n;int cases=0;
 memset(toc,0,sizeof(toc));put32(toc,0x434f5424);put32(toc+4,1);put32(toc+8,3);
 entry(toc,0,0x4000,0x80000,0xfffe,0xfffe);entry(toc,1,0x84000,0x20000,0,2);entry(toc,2,0xa4000,0x20000,1,2);memcpy(original,toc,sizeof(toc));
 assert(G135Select(toc,sizeof(toc),out,&n)==0&&n==2&&out[1].Host1==2);cases++;
 for(int kind=0;kind<13;kind++){
  memcpy(toc,original,sizeof(toc));uint8_t*p=toc+32+48;
  switch(kind){case 0:toc[0]^=1;break;case 1:put32(toc+4,2);break;case 2:put32(toc+8,65);break;case 3:put32(p,0x200000);break;case 4:put32(p+4,0xffffffff);break;case 5:put32(p,0x80000);break;case 6:put16(p+12,1);break;case 7:put32(p+4,0x100001);break;case 8:put32(p,0x84001);break;case 9:put32(p+16,3);break;case 10:put32(p+16,0);break;case 11:put16(p+12,0xfffe);put16(p+14,0xfffe);break;case 12:put32(p,0x1000);break;}
  assert(G135Select(toc,sizeof(toc),out,&n)!=0);cases++;
 }
 memcpy(toc,original,sizeof(toc));assert(G135Select(toc,4095,out,&n)!=0);cases++;
 put16(toc+32+48+12,2);put16(toc+32+48+14,0);assert(!G135Select(toc,sizeof(toc),out,&n)&&out[1].Host0==2);cases++;
 memset(part,0,sizeof(part));put32(part,0x54525024);put16(part+4,2);put32(part+8,0x20000);put32(part+12,32);put32(part+16,0x20000);assert(G135PartHeader(part,out+1));cases++;
 for(int kind=0;kind<5;kind++){
  uint8_t bad[32];memcpy(bad,part,32);
  if(kind==0)bad[0]^=1;if(kind==1)put16(bad+4,1);if(kind==2)put32(bad+8,0x30000);if(kind==3)put32(bad+12,0x30000);if(kind==4)put32(bad+16,0x30000);
  assert(!G135PartHeader(bad,out+1));cases++;
 }
 if(argc==2){FILE*f=fopen(argv[1],"rb");assert(f&&fread(toc,1,4096,f)==4096);assert(fgetc(f)==EOF);fclose(f);assert(!G135Select(toc,sizeof(toc),out,&n)&&n==2);assert(out[0].Offset==0x19f000&&out[0].Bytes==0x60000&&out[0].Host0==0&&out[0].Host1==2);assert(out[1].Offset==0x1000&&out[1].Bytes==0xb0000&&out[1].Host0==0xfffe&&out[1].Host1==0xfffe);cases++;}
 printf("{\"passed\":true,\"cases\":%d,\"native_operations\":0}\n",cases);
}
