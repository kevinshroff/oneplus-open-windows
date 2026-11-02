"""Validate the fixed IC-info header and execute unchanged vendor SPI-read framing."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=a.inputs/'reference-goodix';c=base/'GT9966-goodix_brl_core.c';h=base/'GT9966-goodix_brl_core.h';receipt=json.loads((base/'source-receipt.json').read_text());pins=receipt['files']
assert sha(c)==pins['vendor/oplus/kernel/touchpanel/oplus_touchscreen_v2/Goodix/GT9966/goodix_brl_core.c']['sha256'];assert sha(h)==pins['vendor/oplus/kernel/touchpanel/oplus_touchscreen_v2/Goodix/GT9966/goodix_brl_core.h']['sha256'];s=c.read_text();head=h.read_text()
assert re.search(r'#define\s+GOODIX_IC_INFO_ADDR\s+0x10070',s)and re.search(r'#define\s+GOODIX_IC_INFO_MAX_LEN\s+1024',s)
assert 'length >= GOODIX_IC_INFO_MAX_LEN'in s and 'CHECKSUM_MODE_U8_LE'in s[s.index('static int brl_get_ic_info'):s.index('static int goodix_get_chip_info')]
def extract(name):
 m=re.search(r'^int '+name+r'\([^;]*?\)\s*\{',s,re.M);assert m;i=m.end();d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
body=extract('goodix_spi_read');structs='\n'.join(re.search(r'struct '+name+r'\s*\{.*?\n\};',head,re.S).group()for name in['goodix_ic_info_version','goodix_ic_info_feature','goodix_ic_info_misc'])
for name,value in [('SPI_TRANS_PREFIX_LEN',1),('REGISTER_WIDTH',4),('SPI_READ_DUMMY_LEN',3),('SPI_READ_FLAG',0xf1)]:
 m=re.search(r'^#define\s+'+name+r'\s+(0[xX][0-9a-fA-F]+|[0-9]+)',s+"\n"+head,re.M);assert m and int(m[1],0)==value
assert '(SPI_TRANS_PREFIX_LEN + REGISTER_WIDTH + SPI_READ_DUMMY_LEN)'in s
prefix=r'''
#include "geni_fifo.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#pragma pack(push,1)
'''+structs+r'''
#pragma pack(pop)
#define SPI_READ_PREFIX_LEN 8
#define SPI_READ_FLAG 0xf1
#define GFP_KERNEL 0
#define ENOMEM 12
#define TPD_INFO(...) ((void)0)
struct spi_device{int unused;};struct chip_data_brl{struct spi_device*s_client;};
struct spi_transfer{const void*tx_buf;void*rx_buf;unsigned len,cs_change;};struct spi_message{struct spi_transfer*x;};
static unsigned Allocations,Outstanding,FailAllocation,SyncCalls,Length;static uint32_t Address;static int SyncError;
static void*kzalloc(size_t n,int flags){(void)flags;if(++Allocations==FailAllocation)return NULL;void*p=calloc(1,n);if(p)Outstanding++;return p;}
static void kfree(void*p){if(p){assert(Outstanding);Outstanding--;free(p);}}
static void spi_message_init(struct spi_message*m){m->x=NULL;}
static void spi_message_add_tail(struct spi_transfer*x,struct spi_message*m){assert(!m->x);m->x=x;}
static int spi_sync(struct spi_device*d,struct spi_message*m){unsigned i;uint8_t expected[2048];(void)d;SyncCalls++;assert(m->x&&m->x->len==Length+8&&!m->x->cs_change);assert(!g27_goodix_read_frame(Address,Length,expected,sizeof(expected)));assert(!memcmp(expected,m->x->tx_buf,Length+8));if(SyncError)return SyncError;for(i=0;i<Length+8;i++)((uint8_t*)m->x->rx_buf)[i]=(uint8_t)(i*37);return 0;}
'''
main=r'''
int main(void){struct spi_device d={0};struct chip_data_brl c={&d};uint8_t data[1024];unsigned i,j,k,cases=0;const uint32_t addresses[]={0x10014,0x10070,0x10200};const unsigned lengths[]={1,2,28,153,1015};
 assert(sizeof(struct goodix_ic_info_version)==16&&sizeof(struct goodix_ic_info_feature)==10&&sizeof(struct goodix_ic_info_misc)==114);
 assert(2+sizeof(struct goodix_ic_info_version)+sizeof(struct goodix_ic_info_feature)==28);
 assert(2+16+10+9+114+2==153);
 for(i=0;i<3;i++)for(j=0;j<5;j++){
  Address=addresses[i];Length=lengths[j];Allocations=SyncCalls=0;memset(data,0,sizeof(data));assert(!goodix_spi_read(&c,Address,data,Length)&&!Outstanding&&SyncCalls==1);
  for(k=0;k<Length;k++)assert(data[k]==(uint8_t)((k+8)*37));cases++;
 }
 Address=0x10070;Length=28;
 for(i=1;i<=2;i++){Allocations=SyncCalls=0;FailAllocation=i;assert(goodix_spi_read(&c,Address,data,Length)==-ENOMEM&&!Outstanding&&!SyncCalls);cases++;}
 Allocations=SyncCalls=FailAllocation=0;SyncError=-5;assert(goodix_spi_read(&c,Address,data,Length)==-5&&!Outstanding&&SyncCalls==1);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"fixed_header_bytes\":28,\"minimum_complete_block_bytes\":153,\"maximum_complete_block_bytes\":1023,\"vendor_SPI_read_function_unchanged\":true,\"framing_matches_actual_G46_builder\":true}\n",cases);return 0;}
'''
f=a.output/'source-info.c';f.write_text(prefix+body+main);exe=a.output/'source-info';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(f),str(W/'geni_fifo.c'),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr);r=json.loads(q.stdout);r.update(ASan_UBSan=True,source_commit=receipt['commit'],source_C_sha256=sha(c),source_H_sha256=sha(h),original_SPI_read_body_sha256=hashlib.sha256(body.encode()).hexdigest(),G46_FIFO_sha256=sha(W/'geni_fifo.c'),read_address='0x10070',physical_full_block_checksum_verified=False,native_commands_submitted=0,limits=['Source function allocation/SPI services and RX bytes are modeled.','The fixed28-byte header has no complete IC-info checksum. No addresses/layout from it may be relied on until a later bounded complete-block read and checksum.'])
(a.output/'source-info.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
