"""Run unchanged stock request, clear-IRQ and SPI-write functions without hardware."""
from pathlib import Path
import argparse, hashlib, json, re, subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs',type=Path,required=True)
p.add_argument('--report',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
c=a.inputs/'reference-goodix/GT9966-goodix_brl_core.c'
h=a.inputs/'reference-goodix/GT9966-goodix_brl_core.h'
assert sha(c)=='f0e09004861d89392f163709a64a4effe2da0b7831a2d20f57b41fcbff63674a'
assert sha(h)=='4605c36d099607bfdf912085171b1c8c049ab01cf8762c6446bfee13b9c5eab3'
s=c.read_text();head=h.read_text()
def extract(name):
 m=re.search(r'^(?:static )?int '+name+r'\([^;]*?\)\s*\{',s,re.M);assert m,name
 i=m.end();d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
names=['goodix_spi_write','goodix_reg_write','goodix_clear_irq','goodix_request_event_handler']
bodies={n:extract(n)for n in names}
constants={'REQUEST_EVENT_TYPE_OFFSET':2,'GTP_RQST_CONFIG':1,'GTP_RQST_RESET':3,'GOODIX_REQUEST_EVENT':0x40,'SPI_WRITE_FLAG':0xf0}
for n,v in constants.items():
 m=re.search(r'^#define\s+'+n+r'\s+(0[xX][0-9a-fA-F]+|[0-9]+)',s+'\n'+head,re.M)
 assert m and int(m[1],0)==v,n
assert '#define SPI_WRITE_PREFIX_LEN' in s
assert '(SPI_TRANS_PREFIX_LEN + REGISTER_WIDTH)' in s
report=a.report.read_bytes();assert len(report)==26 and report[:8]==bytes.fromhex('4001000000034400')
assert (sum(report[:6])&65535)==int.from_bytes(report[6:8],'little') and report[2]==0
prefix=r'''
#include "g49_contract.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint32_t u32;
#define GFP_KERNEL 0
#define ENOMEM 12
#define TPD_INFO(...) ((void)0)
#define SPI_WRITE_PREFIX_LEN 5
struct spi_device{int unused;};
struct spi_transfer{const void*tx_buf;void*rx_buf;unsigned len,cs_change;};
struct spi_message{struct spi_transfer*x;};
struct chip_data_brl{struct spi_device*s_client;int rawdiff_mode;
 struct{struct{u32 touch_data_addr;}misc;}ic_info;
 u8 touch_data[26];struct{u8*data;unsigned length;}normal_cfg;};
static unsigned ConfigCalls,ResetCalls,SyncCalls,FailAlloc,Outstanding;
static int SyncError,ConfigError;static uint8_t Frame[6];
static void*kzalloc(size_t n,int f){(void)f;if(FailAlloc)return NULL;void*p=calloc(1,n);if(p)Outstanding++;return p;}
static void kfree(void*p){if(p){assert(Outstanding);Outstanding--;free(p);}}
static void spi_message_init(struct spi_message*m){m->x=NULL;}
static void spi_message_add_tail(struct spi_transfer*x,struct spi_message*m){assert(!m->x);m->x=x;}
static int spi_sync(struct spi_device*d,struct spi_message*m){uint8_t expected[6];assert(G49EventClearFrame(expected,6));(void)d;SyncCalls++;assert(m->x&&m->x->len==6&&!m->x->rx_buf&&!m->x->cs_change);memcpy(Frame,m->x->tx_buf,6);assert(!memcmp(Frame,expected,6));return SyncError;}
static int goodix_send_config(struct chip_data_brl*c,u8*d,unsigned n){assert(d==c->normal_cfg.data&&n==c->normal_cfg.length);ConfigCalls++;return ConfigError;}
static int goodix_reset(struct chip_data_brl*c){(void)c;ResetCalls++;return 0;}
'''
main=r'''
int main(void){struct spi_device d={0};struct chip_data_brl c={0};unsigned i,cases=0;c.s_client=&d;c.ic_info.misc.touch_data_addr=0x10274;
 memcpy(c.touch_data,Actual,26);assert(c.touch_data[0]==GOODIX_REQUEST_EVENT&&c.touch_data[REQUEST_EVENT_TYPE_OFFSET]==0);
 assert(!goodix_request_event_handler(&c)&&!ConfigCalls&&!ResetCalls&&!SyncCalls);cases++;
 assert(!goodix_clear_irq(&c)&&SyncCalls==1&&!Outstanding);cases++;
 for(i=0;i<256;i++){c.touch_data[REQUEST_EVENT_TYPE_OFFSET]=(u8)i;ConfigCalls=ResetCalls=SyncCalls=0;
  assert(!goodix_request_event_handler(&c));assert(ConfigCalls==(i==1)&&ResetCalls==(i==3)&&!SyncCalls);cases++;}
 c.rawdiff_mode=1;SyncCalls=0;assert(goodix_clear_irq(&c)==-1&&!SyncCalls&&!Outstanding);cases++;
 c.rawdiff_mode=0;FailAlloc=1;assert(goodix_clear_irq(&c)==-ENOMEM&&!SyncCalls&&!Outstanding);cases++;
 FailAlloc=0;SyncError=-5;assert(goodix_clear_irq(&c)==-5&&SyncCalls==1&&!Outstanding);cases++;
 c.touch_data[2]=1;ConfigError=-5;ConfigCalls=0;assert(!goodix_request_event_handler(&c)&&ConfigCalls==1);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"captured_request_zero_has_no_config_or_reset_action\":true,\"clear_frame\":[240,0,1,2,116,0],\"TX_only\":true}\n",cases);return 0;}
'''
W=Path(__file__).resolve().parent
src=a.output/'event-source.c'
src.write_text(prefix+'\n'.join('#define '+n+' '+str(v)for n,v in constants.items())+'\nstatic const uint8_t Actual[]={'+','.join(map(str,report))+'};\n'+'\n'.join(bodies.values())+main)
exe=a.output/'event-source'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(W/'g49_contract.c'),str(src),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr)
r=json.loads(q.stdout);r.update(ASan_UBSan=True,unchanged_vendor_functions={n:hashlib.sha256(b.encode()).hexdigest()for n,b in bodies.items()},source_C_sha256=sha(c),source_H_sha256=sha(h),G49_contract_sha256=sha(W/'g49_contract.c'),captured_report_sha256=sha(a.report),native_commands_submitted=0,limits=['Linux allocation and SPI services are modeled; no native write is performed.','Request byte zero takes the vendor default branch. No configuration request is inferred.','The fixed G49 clear-frame builder matches the unchanged vendor SPI-write frame; native GENI behavior is separate evidence.'])
(a.output/'event-source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
