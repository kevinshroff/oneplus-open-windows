/* Host actual-artifact contract test. Full WDM lifecycle is not executed. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "g321_runtime_test.h"
#include "production_admission.inc"
static g196_bytes Read(const char *path){FILE*f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>0);rewind(f);uint8_t*p=malloc((size_t)n);assert(p&&fread(p,1,(size_t)n,f)==(size_t)n);assert(!fclose(f));return(g196_bytes){p,(size_t)n};}
static g196_preflight prepared;static G321_RUNTIME runtime;
int main(int argc,char**argv){
 assert(argc==7);g196_inputs in={Read(argv[1]),Read(argv[2]),Read(argv[3]),Read(argv[4]),Read(argv[5])};g196_bytes rsc=Read(argv[6]);assert(rsc.bytes==20);
 assert(g196_prepare(&in,&prepared)==G196_INPUTS_MATCH);assert(prepared.revision==0x20000&&prepared.soc_id==519&&prepared.source_sku==2&&!prepared.native_ready&&prepared.remaining_native==127);
 g321_plan plan;assert(g321_plan_image(&prepared.image,&plan)==G190_OK);
 /* These assignments are extracted byte-for-byte from the actual transfer
  * and runtime borrow statements. Host fixture carries only tested fields. */
 struct{g196_preflight Inputs;g321_plan Plan;} candidate={prepared,plan},binding={0};
 {__typeof__(candidate)*r=&candidate;__typeof__(binding)*b=&binding;
 #include "production_transfer.inc"
 }
 {__typeof__(binding)*t=&binding;G321_RUNTIME*r=&runtime;
 #include "production_borrow.inc"
 }
 assert(!memcmp(&runtime.Inputs,&prepared,sizeof(prepared)));assert(runtime.Inputs.image.bytes==in.gmu_image.data);assert(!memcmp(&runtime.Plan,&plan,sizeof(plan)));
 runtime.Generation=11;G482_BOARD_INPUT board={11,0x70201,rsc.data,rsc.bytes};assert(G482AdmitBoard(&runtime,&board)==STATUS_SUCCESS&&runtime.BoardAdmitted);
 unsigned cases=1;const uint32_t wrong[]={2,0,1,0x200,0x20001,0x10000,0xffffffff};for(unsigned i=0;i<sizeof(wrong)/sizeof(wrong[0]);i++){runtime.BoardAdmitted=FALSE;runtime.Inputs.revision=wrong[i];assert(G482AdmitBoard(&runtime,&board)==STATUS_NOT_SUPPORTED&&!runtime.BoardAdmitted);cases++;}
 runtime.Inputs=prepared;runtime.BoardAdmitted=FALSE;((uint8_t*)rsc.data)[0]^=1;assert(G482AdmitBoard(&runtime,&board)==STATUS_INVALID_IMAGE_HASH&&!runtime.BoardAdmitted);((uint8_t*)rsc.data)[0]^=1;cases++;
 const uint32_t badsoc[]={0,519+1};for(unsigned i=0;i<2;i++){runtime.Inputs=prepared;runtime.Inputs.soc_id=badsoc[i];assert(G482AdmitBoard(&runtime,&board)==STATUS_NOT_SUPPORTED&&!runtime.BoardAdmitted);cases++;}
 runtime.Inputs=prepared;runtime.Inputs.source_sku=1;assert(G482AdmitBoard(&runtime,&board)==STATUS_NOT_SUPPORTED);cases++;
 runtime.Inputs=prepared;board.Generation++;assert(G482AdmitBoard(&runtime,&board)==STATUS_NOT_SUPPORTED);board.Generation--;cases++;
 board.SourceProfile++;assert(G482AdmitBoard(&runtime,&board)==STATUS_NOT_SUPPORTED);board.SourceProfile--;cases++;
 board.RscBytes--;assert(G482AdmitBoard(&runtime,&board)==STATUS_NOT_SUPPORTED);board.RscBytes++;cases++;
 assert(G482AdmitBoard(&runtime,&board)==STATUS_SUCCESS&&runtime.BoardAdmitted);cases++;
 printf("PASS %u actual-artifact board contract cases; real g196 + g321 planner + production transfer/borrow expressions + actual admission body; no WDM lifecycle/MMIO/runtime proof\n",cases);
 free((void*)in.firmware_fdt.data);free((void*)in.global_smem_first.data);free((void*)in.global_smem_second.data);free((void*)in.command_db.data);free((void*)in.gmu_image.data);free((void*)rsc.data);return 0;
}
