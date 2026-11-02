"""Execute the exact native adapter's address/value policy with modeled registers."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g49_driver.c').read_text()
def function(n):
 m=re.search(r'^static (?:PULONG|int) '+n+r'\(',s,re.M);assert m
 i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
context=re.search(r'typedef struct \{PVOID Maps\[16\];.*?\} G49_PWR_CONTEXT;',s).group()
ranges=re.search(r'static const G49_RANGE G49PowerRanges\[16\]=.*?;',s).group()
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
#include "g49_trial.h"
#include "g49_binding.h"
static unsigned Writes,Reads;static uint32_t Memory[16][4096];
static uint32_t ReadReg(PULONG p){Reads++;return*p;}
static void WriteReg(PULONG p,uint32_t v){Writes++;*p=v;if(p==&Memory[14][0x618/4])Memory[14][0x610/4]&=~v;if(p==&Memory[14][0x648/4])Memory[14][0x640/4]&=~v;}
#define READ_REGISTER_ULONG(p) ReadReg(p)
#define WRITE_REGISTER_ULONG(p,v) WriteReg(p,v)
'''
main=r'''
static unsigned Cases;
static void Send(G49_PWR_CONTEXT*c,const uint8_t*tx,unsigned words){unsigned i,before;uint32_t word;
 for(i=0;i<words;i++){word=(uint32_t)tx[i*4]|((uint32_t)tx[i*4+1]<<8)|((uint32_t)tx[i*4+2]<<16)|((uint32_t)tx[i*4+3]<<24);before=Writes;assert(!G49PowerWrite(c,0xa90700,word^1)&&Writes==before&&c->FifoWords==i);Cases++;assert(G49PowerWrite(c,0xa90700,word)&&c->FifoWords==i+1);Cases++;}
 before=Writes;assert(!G49PowerWrite(c,0xa90700,0)&&Writes==before);Cases++;
}
int main(void){G49_PWR_CONTEXT c;G49_TRIAL_RESULT t;unsigned i,before;uint32_t v;
 const uint32_t denied[][2]={{0xa90600,0},{0xa90600,0x08000000},{0xa90604,4},{0xa90604,2},{0xa90700,0x100f1},{0xa9026c,36},{0xa90270,6},{0xa90270,252},{0xa90e24,0},{0x17100130,0x20},{0xc7b7000,1},{0xb000000,1},{0xf119008,0}};
 memset(&c,0,sizeof(c));memset(&t,0,sizeof(t));c.Trial=&t;c.Result=&t.Power;for(i=0;i<16;i++)c.Maps[i]=Memory[i];assert(!g27_goodix_read_frame(0x10070,242,t.Touch.Tx,252));
 for(i=0;i<sizeof(denied)/sizeof(denied[0]);i++){before=Writes;assert(!G49PowerWrite(&c,denied[i][0],denied[i][1])&&Writes==before);Cases++;}
 Memory[14][0x610/4]=0x80;assert(G49PowerRead(&c,0xa90610,&v)&&v==0x80);assert(G49PowerWrite(&c,0xa90600,0x18000000));assert(!c.HaveM&&!c.HaveS);before=Writes;assert(!G49PowerWrite(&c,0xa90618,0x80)&&Writes==before);Cases++;
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 Send(&c,t.Touch.Tx,63);
 assert(G49PowerRead(&c,0xa90610,&v));before=Writes;assert(!G49PowerWrite(&c,0xa90618,v^1)&&Writes==before);assert(G49PowerWrite(&c,0xa90618,v));before=Writes;assert(!G49PowerWrite(&c,0xa90618,v)&&Writes==before);Cases++;
 Memory[14][0x640/4]=0x0c000000;assert(G49PowerRead(&c,0xa90640,&v));assert(G49PowerWrite(&c,0xa90648,v));Memory[14][0x640/4]=v;assert(G49PowerRead(&c,0xa90640,&v));before=Writes;assert(!G49PowerWrite(&c,0xa90648,v)&&Writes==before);Cases++;
 assert(!g27_goodix_read_frame(0x10274,26,t.Touch.Report.Tx,36));
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 t.Touch.FullBlockChecksumValid=t.Touch.Report.ContractVerified=1;t.Touch.BusQuiescent=0;before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 t.Touch.BusQuiescent=1;assert(G49PowerWrite(&c,0xa9026c,34)&&G49PowerWrite(&c,0xa90270,34));assert(G49PowerWrite(&c,0xa90600,0x18000000));assert(c.CommandUsed==2&&!c.FifoWords&&!c.HaveM&&!c.HaveS&&!c.SAcks);Cases++;
 Send(&c,t.Touch.Report.Tx,9);
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x08000000)&&Writes==before);Cases++;
 memcpy(t.Touch.Report.Rx+8,(uint8_t[]){0x40,1,0,0,0,3,0x44,0},8);t.Touch.Report.Attempted=t.Touch.Report.TransportOk=1;t.Touch.Report.TxDone=t.Touch.Report.RxDone=34;t.Touch.Report.State=4;G49AnalyzeReport(&t.Touch.Report);assert(G49AckEligible(&t.Touch.Report));
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x08000000)&&Writes==before);Cases++;
 t.Touch.Ack.ContractVerified=1;t.Touch.Report.Rx[14]^=1;before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x08000000)&&Writes==before);Cases++;t.Touch.Report.Rx[14]^=1;
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 assert(G49EventClearFrame(t.Touch.Ack.Tx,36));assert(G49PowerWrite(&c,0xa9026c,6));assert(G49PowerWrite(&c,0xa90600,0x08000000));assert(c.CommandUsed==3&&!c.FifoWords&&!c.HaveM&&!c.HaveS&&!c.SAcks);Cases++;
 t.Touch.Ack.Tx[0]^=1;before=Writes;assert(!G49PowerWrite(&c,0xa90700,0x020100f1)&&Writes==before);Cases++;t.Touch.Ack.Tx[0]^=1;
 Send(&c,t.Touch.Ack.Tx,2);
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 t.Touch.Ack.TransportOk=1;before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 t.Touch.Post.ContractVerified=1;assert(!g27_goodix_read_frame(0x10274,8,t.Touch.Post.Tx,36));assert(G49PowerWrite(&c,0xa9026c,16)&&G49PowerWrite(&c,0xa90270,16));assert(G49PowerWrite(&c,0xa90600,0x18000000));Send(&c,t.Touch.Post.Tx,4);
 before=Writes;assert(!G49PowerWrite(&c,0xa90600,0x18000000)&&!G49PowerWrite(&c,0xa90600,0x08000000)&&Writes==before);Cases++;
 Memory[14][0x640/4]=0x0c000000;assert(G49PowerRead(&c,0xa90640,&v));assert(G49PowerWrite(&c,0xa90648,v));Cases++;
 before=Writes;assert(!G49PowerWrite(&c,0xa90604,2)&&Writes==before);assert(G49PowerWrite(&c,0xa90604,4));before=Writes;assert(!G49PowerWrite(&c,0xa90604,4)&&Writes==before);assert(G49PowerWrite(&c,0xa90604,2));before=Writes;assert(!G49PowerWrite(&c,0xa90604,2)&&Writes==before);Cases++;
 before=Reads;assert(!G49PowerRead(&c,0xc7b7000,&v)&&!G49PowerRead(&c,0xc7b7008,&v)&&!G49PowerRead(&c,0xb000000,&v)&&Reads==before);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_adapter_functions_unchanged\":true,\"TX_requires_owned_CMD_and_exact63_9_2_4_profile_words\":true,\"only_fixed_event_zero_write_allowed\":true,\"fresh_report_checksum_and_request_zero_gate_checked\":true,\"four_CMDs_global_one_cancel_abort_one_S_ACK_per_CMD\":true,\"master_ACK_requires_fresh_post_CMD_read\":true,\"unsafe_direct_SPMI_and_AOP_reads_denied\":true,\"native_access\":false}\n",Cases);return 0;}
'''
source=a.output/'policy.c';source.write_text(prefix+context+'\n'+ranges+'\n'+'\n'.join(function(n)for n in ['G49PowerAddress','G49PowerRead','G49PowerWrite'])+'\n'+main);exe=a.output/'policy'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),'-I',str(a.binding.resolve()),str(W/'g49_rsc.c'),str(W/'g49_engine.c'),str(W/'g49_contract.c'),str(W/'geni_fifo.c'),str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr)
report=json.loads(q.stdout);report.update(ASan_UBSan=True,adapter_sha256=hashlib.sha256((W/'g49_driver.c').read_bytes()).hexdigest(),binding_sha256=hashlib.sha256((a.binding/'g49_binding.h').read_bytes()).hexdigest(),limits=['Kernel register macros and mapped pages are modeled CPU memory.','This verifies the actual native policy functions; physical write permissions and cleanup remain separate native evidence.'])
(a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
