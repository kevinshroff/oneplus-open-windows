"""Run unchanged pinned GPIO and AVDD source functions at modeled boundaries."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
assert not a.output.exists();a.output.mkdir(parents=True)
files={'pinctrl':('gpio-G20/private/pinctrl-msm.c','436c1321b9d5f013221e7001ce8894d0ab947b7482679ef6411388b77a989753'),'kalama':('gpio-G20/private/pinctrl-kalama.c','fd48c2e5f669c9f3304074b42578e5b6a498ca303855eb0c1d6d47e17d0785ac'),'touch':('touch-G25/private/touchpanel_common_driver.c','2a52ef695f230b83e41e406f4ab4db280d816024facf31c955e7839c6dcb0ec1')}
text={};hashes={}
for k,(n,h)in files.items():
 f=a.inputs/n;assert hashlib.sha256(f.read_bytes()).hexdigest()==h;text[k]=f.read_text();hashes[n]=h
fields={}
macro=text['kalama'].split('#define PINGROUP(',1)[1].split('\n#define',1)[0]
for k,expect in [('oe_bit',9),('in_bit',0),('out_bit',1),('intr_enable_bit',0),('intr_status_bit',0)]:
 m=re.search(r'\.'+k+r'\s*=\s*(\d+)',macro);assert m and int(m[1])==expect;fields[k]=expect
assert '#define REG_BASE 0x100000' in text['kalama'] and '#define REG_SIZE 0x1000'in text['kalama']
fdt=json.loads((a.inputs/'touch-G25/touch-power-source-resolved.json').read_text())
for candidate in fdt['candidates']:
 node,=[t for t in candidate['touches']if 'spi@a90000/'in t['path']]
 assert node['resources']['enable2v8_gpio']['cells'][1]==10 and node['resources']['reset-gpio']['cells'][1]==24
 assert 'vdd_2v8-supply'not in node['resources']
def extract(t,name):
 m=re.search(r'^(?:static )?(?:int|void) '+name+r'\([^;]*?\)\s*\{',t,re.M);assert m,name
 start=m.start();at=m.end();depth=1
 while depth:
  if t[at]=='{':depth+=1
  if t[at]=='}':depth-=1
  at+=1
 return t[start:at]
functions=[extract(text['pinctrl'],n)for n in ['msm_gpio_direction_output','msm_gpio_direction_input','msm_gpio_get']]
common=extract(text['touch'],'tp_powercontrol_avdd')
head=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
typedef uint32_t u32;
#define BIT(n) (1u<<(n))
struct msm_pingroup{unsigned oe_bit,in_bit,out_bit;};
struct fake_soc{const struct msm_pingroup*groups;};
struct msm_pinctrl{const struct fake_soc*soc;int lock;};
struct gpio_chip{struct msm_pinctrl*pctrl;};
static u32 ctl,io;static int locks,nwrites,reqPin,reqValue,nreq,regError,gpioError,nreg;
static struct{int kind;u32 value;}writes[8];
static struct msm_pinctrl*gpiochip_get_data(struct gpio_chip*c){return c->pctrl;}
#define raw_spin_lock_irqsave(l,f) do{(void)(l);(f)=0;assert(!locks);locks++;}while(0)
#define raw_spin_unlock_irqrestore(l,f) do{(void)(l);(void)(f);assert(locks==1);locks--;}while(0)
static u32 msm_readl_ctl(struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;return ctl;}
static u32 msm_readl_io(struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;return io;}
static void msm_writel_ctl(u32 v,struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;assert(locks==1);writes[nwrites].kind=2;writes[nwrites++].value=v;ctl=v;}
static void msm_writel_io(u32 v,struct msm_pinctrl*p,const struct msm_pingroup*g){(void)p;(void)g;assert(locks==1);writes[nwrites].kind=1;writes[nwrites++].value=v;io=v;}
static struct gpio_chip chip;
'''
bridge=r'''
struct hw_resource{void*avdd;int enable_avdd_gpio;};
#define IS_ERR_OR_NULL(x) ((x)==NULL)
#define TPD_BOOT_INFO(...) do{}while(0)
#define TPD_INFO(...) do{}while(0)
#define EXPORT_SYMBOL(x)
static int regulator_enable(void*x){assert(x);nreg++;return regError;}
static int regulator_disable(void*x){assert(x);nreg++;return regError;}
static int gpio_direction_output(int pin,int value){reqPin=pin;reqValue=value;nreq++;if(gpioError)return gpioError;return msm_gpio_direction_output(&chip,(unsigned)pin,value);}
'''
main=r'''
static void reset(u32 c,u32 i){ctl=c;io=i;locks=nwrites=nreq=nreg=regError=gpioError=0;}
int main(void){
 struct msm_pingroup groups[11];for(int i=0;i<11;i++)groups[i]=(struct msm_pingroup){9,0,1};
 struct fake_soc soc={groups};struct msm_pinctrl pctrl={&soc,0};chip.pctrl=&pctrl;
 unsigned cases=0;u32 controls[]={1,0x201,0x1801};
 for(unsigned j=0;j<3;j++)for(u32 i=0;i<4;i++){
  for(int v=0;v<=1;v++){
   reset(controls[j],i);assert(msm_gpio_direction_output(&chip,10,v)==0);assert(!locks&&nwrites==2);
   assert(writes[0].kind==1&&writes[0].value==((i&~2u)|(v?2u:0u)));assert(writes[1].kind==2&&writes[1].value==(controls[j]|0x200));cases++;
  }
  reset(controls[j],i);assert(msm_gpio_direction_input(&chip,10)==0);assert(!locks&&nwrites==1&&writes[0].kind==2&&writes[0].value==(controls[j]&~0x200u));cases++;
  reset(controls[j],i);assert(msm_gpio_get(&chip,10)==(int)(i&1));assert(nwrites==0&&!locks);cases++;
 }
 for(int on=0;on<=1;on++)for(int mode=0;mode<4;mode++){
  reset(1,0);struct hw_resource r={mode?(void*)1:NULL,10};
  if(mode==2)regError=-5;if(mode==3)gpioError=-6;
  int ret=tp_powercontrol_avdd(&r,on);assert(ret==(mode==2?-5:mode==3?-6:0));
  if(mode==2){assert(nreq==0&&nwrites==0);}else{assert(nreq==1&&reqPin==10&&reqValue==on);if(mode==3)assert(nwrites==0);else assert(nwrites==2);}
  assert(nreg==(mode!=0));cases++;
 }
 printf("{\"passed\":true,\"cases\":%u,\"unchanged_source_functions\":4,\"native_commands\":0}\n",cases);return 0;
}
'''
source=a.output/'gpio-reference.c';source.write_text(head+'\n'.join(functions)+bridge+common+main)
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(source),'-o',str(a.output/'gpio-reference')]
r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str((a.output/'gpio-reference').resolve())],capture_output=True,text=True);assert r.returncode==0,r.stderr
result=json.loads(r.stdout);result.update(source_hashes=hashes,source_fields=fields,source_write_order='IO latch then OE; input restoration clears only OE',AVDD_gpio_raw_on=1,AVDD_gpio_raw_off=0,primary_AVDD_pin=10,primary_reset_pin=24,source_based_control_address='0xf000000+0x100000+0x1000*10=0xf10a000',scope='Unchanged C source with modeled Linux/MMIO/regulator boundaries; no native access or electrical claim')
(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
