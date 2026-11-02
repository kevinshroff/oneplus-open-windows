"""Execute unchanged pinctrl mux/config functions at modeled Linux boundaries."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
src=a.inputs/'gpio-G20/private/pinctrl-msm.c';soc=a.inputs/'gpio-G20/private/pinctrl-kalama.c';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(src)=='436c1321b9d5f013221e7001ce8894d0ab947b7482679ef6411388b77a989753'
assert sha(soc)=='fd48c2e5f669c9f3304074b42578e5b6a498ca303855eb0c1d6d47e17d0785ac'
t=src.read_text();macro=soc.read_text().split('#define PINGROUP(',1)[1].split('\n#define',1)[0]
for field,value in [('mux_bit',2),('pull_bit',0),('drv_bit',6),('egpio_enable',12),('egpio_present',11),('oe_bit',9),('out_bit',1)]:assert int(re.search(r'\.'+field+r'\s*=\s*(\d+)',macro)[1])==value
for name,value in [('MSM_NO_PULL',0),('MSM_PULL_DOWN',1),('MSM_KEEPER',2),('MSM_PULL_UP_NO_KEEPER',2),('MSM_PULL_UP',3)]:assert int(re.search(r'^#define\s+'+name+r'\s+(\d+)',t,re.M)[1])==value
b=json.loads((a.inputs/'spi-G27/platform-binding-v2.json').read_text())
for c in b['candidates']:
 e=next(x for x in c['engines']if x['path'].endswith('/spi@a90000'));assert [x['pin']for x in e['default_mux']]==[44,45,46,47]and all(x['mux_selector']==1 for x in e['default_mux'])
 configs=[x['properties']for x in e['pinctrl_states']['default']if x['path'].endswith('/config')];assert len(configs)==4 and all(x['drive-strength']==[6]and x['bias-pull-down']for x in configs)
def extract(name):
 m=re.search(r'^static int '+name+r'\([^;]*?\)\s*\{',t,re.M);assert m,name;end=m.end();depth=1
 while depth:
  if t[end]=='{':depth+=1
  if t[end]=='}':depth-=1
  end+=1
 return t[m.start():end]
functions=[extract(x)for x in ['msm_pinmux_set_mux','msm_config_reg','msm_config_group_set']]
head=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
typedef uint32_t u32;
#define BIT(n) (1u<<(n))
#define GENMASK(h,l) (((~0u)>>(31-(h)))&((~0u)<<(l)))
#define WARN_ON(v) (v)
#define EINVAL 22
#define ENOTSUPP 524
#define EGPIO_ENABLE 12
#define EGPIO_PRESENT 11
#define I2C_PULL 13
#define MSM_APPS_OWNER 1
#define MSM_REMOTE_OWNER 0
#define MSM_NO_PULL 0
#define MSM_PULL_DOWN 1
#define MSM_KEEPER 2
#define MSM_PULL_UP_NO_KEEPER 2
#define MSM_PULL_UP 3
#define IRQCHIP_STATE_PENDING 1
enum {PIN_CONFIG_BIAS_DISABLE=1,PIN_CONFIG_BIAS_PULL_DOWN,PIN_CONFIG_BIAS_BUS_HOLD,PIN_CONFIG_BIAS_PULL_UP,PIN_CONFIG_DRIVE_OPEN_DRAIN,PIN_CONFIG_DRIVE_STRENGTH,PIN_CONFIG_OUTPUT,PIN_CONFIG_INPUT_ENABLE,MSM_PIN_CONFIG_APPS,MSM_PIN_CONFIG_REMOTE,MSM_PIN_CONFIG_I2C_PULL};
struct msm_pingroup{unsigned mux_bit,pull_bit,drv_bit,oe_bit,od_bit,egpio_present,egpio_enable,nfuncs,out_bit;int funcs[10];};
struct soc{const struct msm_pingroup*groups;unsigned gpio_func;bool pull_no_keeper;};
struct gpio_chip{struct{void*domain;}irq;};
struct msm_pinctrl{const struct soc*soc;struct gpio_chip chip;int lock;void*dev;unsigned long disabled_for_mux[4],skip_wake_irqs[4];};
struct pinctrl_dev{struct msm_pinctrl*p;};
struct irq_data{unsigned hwirq;void*parent_data;};
static u32 control;static int locks,writes;
static struct msm_pinctrl*pinctrl_dev_get_drvdata(struct pinctrl_dev*p){return p->p;}
static unsigned irq_find_mapping(void*d,unsigned g){(void)d;(void)g;return 0;}
static struct irq_data*irq_get_irq_data(unsigned n){(void)n;return NULL;}
static unsigned order_base_2(unsigned n){unsigned o=0;for(unsigned x=1;x<n;x*=2)o++;return o;}
#define test_and_set_bit(...) (abort(),0)
#define test_and_clear_bit(...) (abort(),0)
#define test_bit(...) (abort(),0)
#define disable_irq(...) abort()
#define enable_irq(...) abort()
#define irq_chip_set_parent_state(...) abort()
#define msm_ack_intr_status(...) abort()
#define raw_spin_lock_irqsave(l,f) do{(void)(l);(f)=0;assert(!locks);locks++;}while(0)
#define raw_spin_unlock_irqrestore(l,f) do{(void)(l);(void)(f);assert(locks==1);locks--;}while(0)
static u32 msm_readl_ctl(struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;return control;}
static void msm_writel_ctl(u32 v,struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;assert(locks==1);control=v;writes++;}
#define msm_readl_io(...) (abort(),0u)
#define msm_writel_io(...) abort()
#define dev_err(...) do{}while(0)
static unsigned pinconf_to_config_param(unsigned long c){return(unsigned)(c&0xffff);}
static unsigned pinconf_to_config_argument(unsigned long c){return(unsigned)(c>>16);}
'''
main=r'''
int main(void){
 struct msm_pingroup groups[48];
 for(unsigned i=0;i<48;i++){groups[i]=(struct msm_pingroup){2,0,6,9,10,11,12,10,1,{0,100,101,102,103,104,105,106,107,108}};}
 struct soc soc={groups,0,false};struct msm_pinctrl p={.soc=&soc};struct pinctrl_dev dev={&p};unsigned cases=0;
 for(unsigned pin=44;pin<=47;pin++)for(unsigned drive=2;drive<=16;drive+=2){
  control=1;locks=writes=0;assert(msm_pinmux_set_mux(&dev,100,pin)==0);assert(control==5&&writes==1&&!locks);
  unsigned long configs[]={((unsigned long)drive<<16)|PIN_CONFIG_DRIVE_STRENGTH,PIN_CONFIG_BIAS_PULL_DOWN};
  assert(msm_config_group_set(&dev,pin,configs,2)==0);assert(control==(5u|((drive/2-1)<<6)));assert(writes==3&&!locks);if(drive==6)assert(control==0x85);cases++;
 }
 control=1;writes=locks=0;unsigned long invalid=(18ul<<16)|PIN_CONFIG_DRIVE_STRENGTH;assert(msm_config_group_set(&dev,44,&invalid,1)==-EINVAL&&writes==0);cases++;
 control=0x801;writes=locks=0;assert(msm_pinmux_set_mux(&dev,100,44)==0&&control==0x1805);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"unchanged_functions\":3,\"primary_6mA_mux1_pulldown\":133}\n",cases);return 0;
}
'''
source=a.output/'pin-reference.c';source.write_text(head+'\n#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wunused-parameter"\n#pragma clang diagnostic ignored "-Wsign-compare"\n'+'\n'.join(functions)+'\n#pragma clang diagnostic pop\n'+main)
r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(source),'-o',str(a.output/'pin-reference')],capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str((a.output/'pin-reference').resolve())],capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
report=json.loads(r.stdout);report.update(source_sha256=sha(src),soc_source_sha256=sha(soc),FDT_binding_sha256=sha(a.inputs/'spi-G27/platform-binding-v2.json'),ASan_UBSan=True,actual_unchanged_source_executed=True,normal_register_value='0x85',normal_fields={'mux_selector':1,'drive_mA':6,'pull_down':1,'OE':0,'EGPIO_present':0},limits=['Linux service/MMIO boundaries, enum names and pin groups are explicit fixtures.','IRQ-connected paths trap; they are not exercised or qualified.','Final-state equivalence only: diagnostic combines mux/drive into one fixed control write.'])
(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
