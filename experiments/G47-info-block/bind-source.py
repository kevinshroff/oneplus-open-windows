"""Bind reset/power/IRQ-ack semantics and prior native foundations to G47."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess,importlib.util
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;G=a.inputs;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();j=lambda p:json.loads(p.read_text())
binding=j(G/'spi-G27/source-binding.json');path='reference-goodix/GT9966-goodix_brl_core.c';good=G/path;assert sha(good)==binding['files'][path]['sha256'];pin=G/'gpio-G20/private/pinctrl-msm.c';kalama=G/'gpio-G20/private/pinctrl-kalama.c';assert sha(pin)=='436c1321b9d5f013221e7001ce8894d0ab947b7482679ef6411388b77a989753'and sha(kalama)=='fd48c2e5f669c9f3304074b42578e5b6a498ca303855eb0c1d6d47e17d0785ac'
def extract(s,name):
 m=re.search(r'^static (?:int|void) '+name+r'\([^;]*?\)\s*\{',s,re.M);assert m,name;cur=m.end();depth=1
 while depth:
  if s[cur]=='{':depth+=1
  elif s[cur]=='}':depth-=1
  cur+=1
 return s[m.start():cur]
funcs=[extract(good.read_text(),n)for n in['goodix_reset','goodix_power_control']]+[extract(pin.read_text(),'msm_ack_intr_status')]
head=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
#define BIT(n) (1u<<(n))
#define TPD_INFO(...) do{}while(0)
#define CONFIG_ARCH_QTI_VM 1
#define PEN_UP 0
struct hw_resource{int reset_gpio;};
struct chip_data_brl{struct hw_resource*hw_res;bool halt_status,gt_temp_enable;int pen_state,irq;};
static int events[64],n;static void add(int v){assert(n<64);events[n++]=v;}
static int gpio_is_valid(int pin){assert(pin==24);return 1;}
static int gpio_direction_output(int pin,int value){assert(pin==24);add(200+value);return 0;}
static void msleep(int ms){add(ms);}
static void usleep_range(int lo,int hi){assert(hi==lo+1000);assert(lo==10000||lo==50000);add(lo/1000);}
static void disable_irq(int irq){assert(irq==25);add(300);}
static int tp_powercontrol_vddi(struct hw_resource*h,bool on){assert(h->reset_gpio==24);add(100+on);return 0;}
static int tp_powercontrol_avdd(struct hw_resource*h,bool on){assert(h->reset_gpio==24);add(110+on);return 0;}
struct msm_pinctrl{int unused;};struct msm_pingroup{bool intr_ack_high;unsigned intr_status_bit;};static u32 ack;
static void msm_writel_intr_status(u32 v,struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;ack=v;}
'''
tail=r'''
int main(void){
 struct hw_resource h={24};struct chip_data_brl c={&h,true,false,1,25};
 int expected[]={101,10,111,10,200,15,201,50,100,200,300,50,110,10,100};
 assert(goodix_power_control(&c,true)==0);assert(goodix_power_control(&c,false)==0);assert(n==15);
 for(int i=0;i<n;i++)assert(events[i]==expected[i]);
 struct msm_pinctrl p={0};unsigned cases=1;
 for(unsigned high=0;high<=1;high++)for(unsigned bit=0;bit<8;bit++){struct msm_pingroup g={high!=0,bit};msm_ack_intr_status(&p,&g);assert(ack==(high?BIT(bit):0));cases++;}
 struct msm_pingroup platform={false,0};msm_ack_intr_status(&p,&platform);assert(ack==0);
 printf("{\"passed\":true,\"cases\":%u,\"unchanged_vendor_functions\":3,\"low_ms\":15,\"high_ms\":150,\"reset_low_before_AVDD_off_ms\":50,\"platform_IRQ_ack_value\":0}\n",cases);return 0;}
'''
source=a.output/'reference.c';source.write_text(head+'\n'.join(funcs)+tail);exe=a.output/'reference';q=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.stdout,q.stderr);report=json.loads(q.stdout)
macro=kalama.read_text().split('#define PINGROUP(',1)[1].split('\n#define',1)[0];assert '.intr_ack_high'not in macro and re.search(r'\.intr_status_bit\s*=\s*0',macro)and re.search(r'\.intr_raw_status_bit\s*=\s*4',macro)
assert (W/'geni_fifo.h').read_bytes()==(G/'spi-G27/geni_fifo.h').read_bytes()
# G47 also admits only masked M80 at start, with bit7 enable clear. Check semantic
# tokens independently of comments; framing, packing and recovery stay intact.
old=(G/'spi-G27/geni_fifo.c').read_text();new=(W/'geni_fifo.c').read_text()
old=old.replace('#define IRQ_EXPECTED (IRQ_DONE|IRQ_CANCEL|IRQ_ABORT|IRQ_RX|IRQ_TX)\n','').replace('if(irq&IRQ_ERROR||irq&~(IRQ_EXPECTED|IRQ_ERROR))','if(irq&IRQ_ERROR)')
old=old.replace('{0x610,0xffffffff,0}', '{0x610,0xffffff7f,0}, {0x614,BIT(7),0}')
tokens=lambda x:re.sub(r'\s+','',re.sub(r'/\*.*?\*/','',x,flags=re.S))
assert tokens(old)==tokens(new)
report['FIFO_G47_only_semantic_change']='Retain fatal errors and full lengths; follow vendor raw IRQ ACKs, and permit only masked M80 at start while requiring bit7 enable clear.'
report['FIFO_G47_sha256']=sha(W/'geni_fifo.c')
for name in['observer','rsc']:assert (W/('g47_'+name+'.c')).read_text().replace('G47','G38').replace('g47','g38')==(G/'power-G38'/('g38_'+name+'.c')).read_text()
state=j(G/'power-G38/native-qualification.json');assert state['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'and state['power']['restored']==1 and state['power']['client_after']==[1800,7,0x80000000]
decoder=G/'fdt-analysis/fdtree.py';spec=importlib.util.spec_from_file_location('g47fdt',decoder);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
assert 'arg = (arg / 2) - 1;'in pin.read_text()
active=[]
for candidate in binding['candidates']:
 d=G/('fdt-analysis/private/kalama-candidate-%d-first.dtb'%candidate['candidate']);assert sha(d)==candidate['sha256'];f=mod.Fdt.read(d);ph=f.phandles();child='/soc/qcom,qupv3_1_geni_se@ac0000/spi@a90000/goodix_gt9966@0';rows={}
 for handle in f.cells(child,'pinctrl-0'):
  parent=ph[handle]
  for node,props in f.nodes.items():
   if not node.startswith(parent+'/')or 'drive-strength'not in props:continue
   gpio=f.strings(node,'pins');assert len(gpio)==1;number=int(gpio[0][4:]);drive=f.cells(node,'drive-strength')[0];assert drive in[6,8]
   pull=1 if 'bias-pull-down'in props else 0 if 'bias-disable'in props else None;assert pull is not None
   oe=1 if 'output-low'in props else 0;control=((drive//2-1)<<6)|pull|(oe<<9)
   rows[str(number)]={'source_path':node,'drive_mA':drive,'bias':'pull-down'if pull else'disabled','output_enable':oe,'control':control}
 assert {k:v['control']for k,v in rows.items()}=={'10':0x81,'25':0xc0,'24':0x2c0}
 active.append({'candidate':candidate['candidate'],'DTB_sha256':sha(d),'active_controls':rows})
report['both_candidates_active_gpio_profile']=active
report['AVDD_input_then_output_controls']=[0x81,0x281]
report['reset_output_control']=0x2c0
report['IRQ25_input_control']=0xc0
report['original_controls_restored_after_probe']=[1,0x201,1]
report.update(native_commands_submitted=0,source_sha256={str(p.relative_to(G)):sha(p)for p in[good,pin,kalama,G/'spi-G27/geni_fifo.c',G/'power-G38/native-qualification.json',G/'engine-G37/native-qualification.json']},original_functions_sha256=[hashlib.sha256(f.encode()).hexdigest()for f in funcs],platform_GPIO_IRQ_enabled_and_raw_status_bits_must_remain_zero=True,limits=['Vendor function bodies are unchanged; Linux services, GPIO and supply calls are modeled.','Acknowledging GPIO25 status0 is conditional on an owned latched bit after reset-low with IRQ masked; native permission remains to be observed.','No firmware write, chip configuration write or repeated SPI version command is authorized by this recipe.'])
(a.output/'source-binding.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in['passed','cases','unchanged_vendor_functions','platform_IRQ_ack_value']}))
