/* Actual validator independently executes over native raw records on the Mac.
 * Time/role arguments are extracted from recorded native protocol fields. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "health_capture.h"
#include "health_recheck.h"
static void Read(const char*p,void*b,size_t n){FILE*f=fopen(p,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF&&!fclose(f));}
int main(int argc,char**argv){
 assert(argc==10);uint8_t*c=malloc(CH_CONFIG_BYTES),*g=malloc(CH_GAUGE_BYTES);assert(c&&g);
 Read(argv[1],c,CH_CONFIG_BYTES);Read(argv[2],g,CH_GAUGE_BYTES);
 uint64_t nonce=strtoull(argv[3],NULL,16),now=strtoull(argv[4],NULL,10),old=strtoull(argv[5],NULL,16),stamp=strtoull(argv[6],NULL,10),apply=strtoull(argv[7],NULL,10);uint32_t role=(uint32_t)strtoul(argv[8],NULL,10);CH_HEALTH h;
 uint32_t code=CHValidate(c,CH_CONFIG_BYTES,g,CH_GAUGE_BYTES,nonce,now,old,stamp,role,&h);assert(code==CH_OK);
 if(role!=CH_OBSERVE)assert(CHRecheck(&h,nonce,apply,old,stamp,role)==CH_OK);
 FILE*f=fopen(argv[9],"wbx");assert(f&&fwrite(&h,1,sizeof(h),f)==sizeof(h)&&!fclose(f));
 printf("{\"passed\":true,\"role\":%u,\"capture_bytes\":%zu,\"independent_C_validation\":true,\"rechecked_at_native_snapshot\":%s}\n",role,sizeof(h),role==CH_OBSERVE?"false":"true");free(c);free(g);return 0;
}
