"""Execute the unchanged pinned SPI ISR at modeled MMIO/service boundaries."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
binding=json.loads((a.inputs/'spi-G27/source-binding.json').read_text());paths=['bus-G24/private/spi-msm-geni.c','bus-G24/private/qcom-geni-se.h'];texts={}
for n in paths:
 b=(a.inputs/n).read_bytes();assert hashlib.sha256(b).hexdigest()==binding['files'][n]['sha256'];texts[n]=b.decode()
spi=texts[paths[0]];head=texts[paths[1]];start=spi.index('static irqreturn_t geni_spi_irq(');pos=spi.index('{',start)+1;depth=1
while depth:
 depth+=(spi[pos]=='{')-(spi[pos]=='}');pos+=1
body=spi[start:pos]
names=sorted(set(re.findall(r'\b(?:M_[A-Z0-9_]+|SE_[A-Z0-9_]+|TX_DMA_DONE|RX_DMA_DONE)\b',body)))
macros=[]
for n in names:
 m=re.search(r'^#define\s+'+re.escape(n)+r'\s+([^\n]+)',head,re.M);assert m,n;macros.append('#define '+n+' '+m[1])
enum=re.search(r'enum geni_se_xfer_mode \{.*?\n\};',head,re.S).group()
prefix=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
typedef uint32_t u32;typedef int irqreturn_t;
#define BIT(n) (UINT32_C(1)<<(n))
#define IRQ_HANDLED 1
#define SPI_LOG_DBG(...) ((void)0)
struct spi_geni_master {void *base,*dev,*ipc;int cur_xfer_mode;bool cmd_done;u32 tx_rem_bytes,rx_rem_bytes;int xfer_done;};
static u32 Raw,Ack,ReadCount,WriteCount,Rx,Tx,Completed,Order;
static bool pm_runtime_status_suspended(void*p){(void)p;return false;}
static void geni_spi_handle_rx(struct spi_geni_master*m){assert(!WriteCount);m->rx_rem_bytes=0;Rx++;Order=1;}
static void geni_spi_handle_tx(struct spi_geni_master*m){assert(!WriteCount);m->tx_rem_bytes=0;Tx++;Order=1;}
static void complete(int*p){(void)p;assert(WriteCount==1);Completed++;}
'''
services=r'''
static u32 geni_read_reg(void*p,u32 at){(void)p;assert(at==SE_GENI_M_IRQ_STATUS);ReadCount++;return Raw;}
static void geni_write_reg(u32 value,void*p,u32 at){(void)p;assert(at==SE_GENI_M_IRQ_CLEAR);Ack=value;WriteCount++;Order=2;}
'''
main=r'''
int main(void){
 const u32 cases[]={0,0x80,0x200000,0x40000080,0x0c200001,0x0c200011,0x200080,0x0c000000,0xffffffff};
 unsigned i;for(i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
  struct spi_geni_master m={0};Raw=cases[i];Ack=ReadCount=WriteCount=Rx=Tx=Completed=Order=0;m.cur_xfer_mode=GENI_SE_FIFO;
  assert(geni_spi_irq(0,&m)==IRQ_HANDLED);assert(ReadCount==1&&WriteCount==1&&Ack==Raw&&Order==2);
  assert(Rx==!!(Raw&(BIT(26)|BIT(27)))&&Tx==!!(Raw&BIT(30)));
  assert(Completed==!!(Raw&(BIT(0)|BIT(4)|BIT(5))));
 }
 puts("{\"passed\":true,\"cases\":9,\"source_ISR_body_unchanged\":true,\"whole_raw_IRQ_ACK_after_handlers\":true,\"bit7_or_bit21_alone_not_source_failure\":true,\"native_access\":false}");return 0;
}
'''
source=a.output/'source-isr.c';source.write_text(prefix+'\n'.join(macros)+'\n'+enum+'\n'+services+'\n'+body+'\n'+main);exe=a.output/'source-isr'
r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert not r.returncode,r.stderr
r=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not r.returncode and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout);report.update(ASan_UBSan=True,source_SHA256={n:hashlib.sha256((a.inputs/n).read_bytes()).hexdigest()for n in paths},original_ISR_body_SHA256=hashlib.sha256(body.encode()).hexdigest(),source_start_line=spi[:start].count('\n')+1,limits=['MMIO, FIFO handlers, runtime power and completions are modeled services.','This establishes source control flow, not physical bit21 meaning, controller identity or transfer success.','G47 retains stricter fatal-error and complete-length checks than this source ISR.'])
(a.output/'source-irq.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
