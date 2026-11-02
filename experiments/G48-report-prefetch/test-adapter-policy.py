"""Execute the exact native adapter's address/value policy with modeled registers."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g48_driver.c').read_text()
def function(n):
 m=re.search(r'^static (?:PULONG|int) '+n+r'\(',s,re.M);assert m
 i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{PVOID Maps\[16\];.*?\} G48_PWR_CONTEXT;',s).group()
ranges=re.search(r'static const G48_RANGE G48PowerRanges\[16\]=.*?;',s).group()
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
#include "g48_trial.h"
#include "g48_binding.h"
static unsigned Writes,Reads;static uint32_t Memory[16][4096];
static uint32_t ReadReg(PULONG p){Reads++;return*p;}
static void WriteReg(PULONG p,uint32_t v){Writes++;*p=v;if(p==&Memory[14][0x618/4])Memory[14][0x610/4]&=~v;if(p==&Memory[14][0x648/4])Memory[14][0x640/4]&=~v;}
#define READ_REGISTER_ULONG(p) ReadReg(p)
#define WRITE_REGISTER_ULONG(p,v) WriteReg(p,v)
'''
main=r'''
int main(void){G48_PWR_CONTEXT c;G48_TRIAL_RESULT t;unsigned i,cases=0,before;uint32_t v,word;
 const uint32_t denied[][2]={{0xa90600,0},{0xa90604,4},{0xa90604,2},{0xa90700,0x100f1},{0xa9026c,36},{0xa90270,252},{0xa90e24,0},{0x17100130,0x20},{0xc7b7000,1},{0xb000000,1},{0xf119008,0}};
 memset(&c,0,sizeof(c));memset(&t,0,sizeof(t));c.Trial=&t;c.Result=&t.Power;for(i=0;i<16;i++)c.Maps[i]=Memory[i];assert(!g27_goodix_read_frame(0x10070,242,t.Touch.Tx,252));
 for(i=0;i<sizeof(denied)/sizeof(denied[0]);i++){before=Writes;assert(!G48PowerWrite(&c,denied[i][0],denied[i][1])&&Writes==before);cases++;}
 Memory[14][0x610/4]=0x80;assert(G48PowerRead(&c,0xa90610,&v)&&v==0x80);assert(G48PowerWrite(&c,0xa90600,0x18000000));assert(!c.HaveM&&!c.HaveS);before=Writes;assert(!G48PowerWrite(&c,0xa90618,0x80)&&Writes==before);cases++;
 before=Writes;assert(!G48PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);cases++;
 for(i=0;i<63;i++){
  const uint8_t*tx=t.Touch.Tx+i*4;word=(uint32_t)tx[0]|((uint32_t)tx[1]<<8)|((uint32_t)tx[2]<<16)|((uint32_t)tx[3]<<24);
  before=Writes;assert(!G48PowerWrite(&c,0xa90700,word^1)&&Writes==before&&c.FifoWords==i);cases++;
  assert(G48PowerWrite(&c,0xa90700,word)&&c.FifoWords==i+1);cases++;
 }
 before=Writes;assert(!G48PowerWrite(&c,0xa90700,0)&&Writes==before);cases++;
 assert(G48PowerRead(&c,0xa90610,&v));before=Writes;assert(!G48PowerWrite(&c,0xa90618,v^1)&&Writes==before);assert(G48PowerWrite(&c,0xa90618,v));before=Writes;assert(!G48PowerWrite(&c,0xa90618,v)&&Writes==before);cases++;
 Memory[14][0x640/4]=0x0c000000;assert(G48PowerRead(&c,0xa90640,&v));assert(G48PowerWrite(&c,0xa90648,v));Memory[14][0x640/4]=v;assert(G48PowerRead(&c,0xa90640,&v));before=Writes;assert(!G48PowerWrite(&c,0xa90648,v)&&Writes==before);cases++;
 assert(!g27_goodix_read_frame(0x10274,26,t.Touch.Report.Tx,36));
 before=Writes;assert(!G48PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);cases++;
 t.Touch.FullBlockChecksumValid=t.Touch.Report.ContractVerified=1;t.Touch.BusQuiescent=0;before=Writes;assert(!G48PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);cases++;
 t.Touch.BusQuiescent=1;assert(G48PowerWrite(&c,0xa9026c,34)&&G48PowerWrite(&c,0xa90270,34));assert(G48PowerWrite(&c,0xa90600,0x18000000));assert(c.CommandUsed==2&&!c.FifoWords&&!c.HaveM&&!c.HaveS&&!c.SAcks);cases++;
 for(i=0;i<9;i++){const uint8_t*tx=t.Touch.Report.Tx+i*4;word=(uint32_t)tx[0]|((uint32_t)tx[1]<<8)|((uint32_t)tx[2]<<16)|((uint32_t)tx[3]<<24);before=Writes;assert(!G48PowerWrite(&c,0xa90700,word^1)&&Writes==before&&c.FifoWords==i);cases++;assert(G48PowerWrite(&c,0xa90700,word)&&c.FifoWords==i+1);cases++;}
 before=Writes;assert(!G48PowerWrite(&c,0xa90700,0)&&!G48PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);cases++;
 Memory[14][0x640/4]=0x0c000000;assert(G48PowerRead(&c,0xa90640,&v));assert(G48PowerWrite(&c,0xa90648,v));cases++;
 before=Writes;assert(!G48PowerWrite(&c,0xa90604,2)&&Writes==before);assert(G48PowerWrite(&c,0xa90604,4));before=Writes;assert(!G48PowerWrite(&c,0xa90604,4)&&Writes==before);assert(G48PowerWrite(&c,0xa90604,2));before=Writes;assert(!G48PowerWrite(&c,0xa90604,2)&&Writes==before);cases++;
 before=Reads;assert(!G48PowerRead(&c,0xc7b7000,&v)&&!G48PowerRead(&c,0xc7b7008,&v)&&!G48PowerRead(&c,0xb000000,&v)&&Reads==before);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_adapter_functions_unchanged\":true,\"TX_requires_owned_CMD_and_exact63_then9_profile_words\":true,\"extra_or_changed_TX_words_denied_before_MMIO\":true,\"two_CMD_global_one_cancel_abort_and_one_S_ACK_per_CMD\":true,\"master_ACK_requires_fresh_post_CMD_read\":true,\"unsafe_direct_SPMI_and_AOP_reads_denied\":true,\"native_access\":false}\n",cases);return 0;}
'''
source=a.output/'policy.c';source.write_text(prefix+context+'\n'+ranges+'\n'+'\n'.join(function(n)for n in ['G48PowerAddress','G48PowerRead','G48PowerWrite'])+'\n'+main);exe=a.output/'policy'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),'-I',str(a.binding.resolve()),str(W/'g48_rsc.c'),str(W/'g48_engine.c'),str(W/'geni_fifo.c'),str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr)
report=json.loads(q.stdout);report.update(ASan_UBSan=True,adapter_sha256=hashlib.sha256((W/'g48_driver.c').read_bytes()).hexdigest(),binding_sha256=hashlib.sha256((a.binding/'g48_binding.h').read_bytes()).hexdigest(),limits=['Kernel register macros and mapped pages are modeled CPU memory.','This verifies the actual native policy functions; physical write permissions and cleanup remain separate native evidence.'])
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
