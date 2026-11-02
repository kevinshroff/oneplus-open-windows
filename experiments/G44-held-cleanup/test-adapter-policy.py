"""Execute the exact native adapter's address/value policy with modeled registers."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g44_driver.c').read_text()
def function(n):
 m=re.search(r'^static (?:PULONG|int) '+n+r'\(',s,re.M);assert m
 i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{PVOID Maps\[16\];.*?\} G44_PWR_CONTEXT;',s).group()
ranges=re.search(r'static const G44_RANGE G44PowerRanges\[16\]=.*?;',s).group()
prefix=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint32_t ULONG;typedef uint32_t*PULONG;typedef uint8_t UCHAR;typedef uint8_t*PUCHAR;typedef void*PVOID;typedef uint64_t ULONGLONG;typedef size_t SIZE_T;typedef int BOOLEAN;
#define FALSE 0
#define TRUE 1
#include "g44_recovery.h"
#include "g44_binding.h"
#include "g44_recovery_binding.h"
static unsigned Writes,Reads;static uint32_t Memory[16][4096];
static uint32_t ReadReg(PULONG p){Reads++;return*p;}
static void WriteReg(PULONG p,uint32_t v){Writes++;*p=v;if(p==&Memory[14][0x618/4])Memory[14][0x610/4]&=~v;if(p==&Memory[14][0x648/4])Memory[14][0x640/4]&=~v;}
#define READ_REGISTER_ULONG(p) ReadReg(p)
#define WRITE_REGISTER_ULONG(p,v) WriteReg(p,v)
'''
main=r'''
int main(void){
 G44_PWR_CONTEXT c;G44_TRIAL_RESULT t;unsigned i,cases=0,before;uint32_t v;
 const uint32_t denied[][2]={{0xa90600,0x18000000},{0xa90604,4},{0xa90604,2},{0xa90700,0x000100f1},{0x17a20d3c,1},{0x152008,0x44302380},{0xf12c000,0x85},{0xf10a000,0x281},{0xf118000,0x2c0},{0xf119000,0xc0},{0xf10a004,2},{0xf118004,2},{0xa9026c,36},{0xa90270,36},{0x17100130,0x20},{0xc7b7000,1},{0xb000000,1},{0x17a20d04,1}};
 memset(&c,0,sizeof(c));memset(&t,0,sizeof(t));c.Trial=&t;c.Result=&t.Power;
 for(i=0;i<16;i++)c.Maps[i]=Memory[i];
 for(i=0;i<sizeof(denied)/sizeof(denied[0]);i++){before=Writes;assert(!G44PowerWrite(&c,denied[i][0],denied[i][1])&&Writes==before);cases++;}
 for(i=0;i<24;i++){
  before=Writes;assert(!G44PowerWrite(&c,0xa90000+G44RecoveryEngineOffsets[i],G44OriginalEngine[i]^1u)&&Writes==before);cases++;
  assert(G44PowerWrite(&c,0xa90000+G44RecoveryEngineOffsets[i],G44OriginalEngine[i]));cases++;
 }
 before=Reads;assert(!G44PowerRead(&c,0xc7b7000,&v)&&!G44PowerRead(&c,0xc7b7008,&v)&&!G44PowerRead(&c,0xb000000,&v)&&Reads==before);cases++;
 Memory[14][0x610/4]=0x80;assert(G44PowerRead(&c,0xa90610,&v)&&v==0x80);before=Writes;assert(!G44PowerWrite(&c,0xa90618,0x80)&&Writes==before);cases++;
 c.OwnedPrior=1;assert(!G44PowerWrite(&c,0xa90618,0x81));assert(G44PowerWrite(&c,0xa90618,0x80));cases++;
 Memory[14][0x610/4]=0x80;assert(G44PowerRead(&c,0xa90610,&v));before=Writes;assert(!G44PowerWrite(&c,0xa90618,v)&&Writes==before);cases++;
 Memory[14][0x640/4]=0x0c000000;assert(G44PowerRead(&c,0xa90640,&v));assert(!G44PowerWrite(&c,0xa90648,v|1));assert(G44PowerWrite(&c,0xa90648,v));cases++;
 Memory[14][0x640/4]=0x0c000000;assert(G44PowerRead(&c,0xa90640,&v));before=Writes;assert(!G44PowerWrite(&c,0xa90648,v)&&Writes==before);cases++;
 assert(G44PowerWrite(&c,0x17a20d3c,0)&&G44PowerWrite(&c,0x17a20d3c,0x60000001));cases++;
 assert(G44PowerWrite(&c,0x152008,0x40302380)&&G44PowerWrite(&c,0x152008,0x40102380)&&G44PowerWrite(&c,0x152008,0x40002380));cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_adapter_functions_unchanged\":true,\"SPI_CMD_cancel_FIFO_and_supply_enable1_denied\":true,\"clock_pad_activation_denied\":true,\"only_original_engine_values_allowed\":true,\"IRQ_ACKs_owned_observed_and_one_each\":true,\"unsafe_direct_SPMI_and_AOP_reads_denied\":true,\"native_access\":false}\n",cases);return 0;
}
'''
source=a.output/'policy.c';source.write_text(prefix+context+'\n'+ranges+'\n'+'\n'.join(function(n)for n in ['G44PowerAddress','G44PowerRead','G44PowerWrite'])+'\n'+main);exe=a.output/'policy'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),'-I',str(a.binding.resolve()),str(W/'g44_rsc.c'),str(W/'g44_engine.c'),str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr)
report=json.loads(q.stdout);report.update(ASan_UBSan=True,adapter_sha256=hashlib.sha256((W/'g44_driver.c').read_bytes()).hexdigest(),recovery_binding_sha256=hashlib.sha256((a.binding/'g44_recovery_binding.h').read_bytes()).hexdigest(),limits=['Kernel register macros and mapped pages are modeled CPU memory.','This verifies the actual native policy functions; physical write permissions and cleanup remain separate native evidence.'])
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
