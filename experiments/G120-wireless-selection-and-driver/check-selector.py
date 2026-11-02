"""Compile exact OEM selector/getter bodies with explicit OF/GPIO service models."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
main=(a.source/'main.c').read_bytes();power=(a.source/'power.c').read_bytes();bus=(a.source/'bus.h').read_text()
assert sha(main)=='6374b7a2049af974611190813639b8c932937367718f1e4a23679d099fc895c7'
assert sha(power)=='1fe9e677a9e30a6ca3502f34aa727ffc76bffdcbe5e13b7b03bd9b036aa74c84'
assert re.search(r'#define QCA6490_DEVICE_ID\s+0x1103',bus)and re.search(r'#define KIWI_DEVICE_ID\s+0x1107',bus)
getter=re.search(r'^int cnss_get_wlan_sw_ctrl\(.*?^\}',power.decode(),re.M|re.S)[0]
selector=re.search(r'^static int cnss_get_dev_cfg_node\(.*?^\}',main.decode(),re.M|re.S)[0]
prefix=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;typedef uint8_t u8;
#define CNSS_DTT_CONVERGED 1
#define QCA6490_DEVICE_ID 0x1103
#define KIWI_DEVICE_ID 0x1107
#define CNSS_HSP_DEVICE_TYPE 1
#define CNSS_HMT_DEVICE_TYPE 2
#define WLAN_SW_CTRL_GPIO "qcom,wlan-sw-ctrl-gpio"
#define cnss_pr_dbg(...) ((void)0)
#define cnss_pr_err(...) ((void)0)
struct device_node{const char*name;struct device_node*child,*next;int available,count,read_error;u32 ids[3];};
struct device{struct device_node*of_node;};struct platform_device{struct device dev;};
struct cnss_pinctrl_info{int wlan_sw_ctrl_gpio;};
struct cnss_plat_data{int dt_type;struct platform_device*plat_dev;struct cnss_pinctrl_info pinctrl_info;unsigned long device_id;};
static int gpio_present=1,gpio_number=83,gpio_value,gpio_reads,invalid_gpio_reads,updates,last_type;
static void*of_find_property(struct device_node*n,const char*k,void*l){(void)n;(void)l;assert(!strcmp(k,WLAN_SW_CTRL_GPIO));return gpio_present?&gpio_present:NULL;}
static int of_get_named_gpio(struct device_node*n,const char*k,int i){(void)n;assert(!strcmp(k,WLAN_SW_CTRL_GPIO)&&i==0);return gpio_number;}
static int gpio_get_value(int pin){gpio_reads++;if(pin<0)invalid_gpio_reads++;return gpio_value;}
static struct device_node*available(struct device_node*n){while(n&&!n->available)n=n->next;return n;}
#define for_each_available_child_of_node(p,c) for(c=available((p)->child);c;c=available(c->next))
static int of_property_count_u32_elems(struct device_node*n,const char*k){assert(!strcmp(k,"supported-ids"));return n->count;}
static int of_property_read_u32_index(struct device_node*n,const char*k,u32 i,u32*out){assert(!strcmp(k,"supported-ids")&&i<(u32)n->count&&i<3);if(n->read_error)return -EINVAL;*out=n->ids[i];return 0;}
static void cnss_utils_update_device_type(int t){updates++;last_type=t;}
'''
suffix=r'''
int main(void){
 const char*cases[]={"low","high","reverse-low","reverse-high","non-converged","missing-low-id","missing-high-id","empty-ids","property-read-error","unavailable-low","unrelated-name","no-children","missing-gpio-property","deferred-gpio","negative-gpio-value"};
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
  const char*name=cases[i];struct device_node low={.name="chip_cfg",.available=1,.count=1,.ids={KIWI_DEVICE_ID}},high={.name="chip_cfg",.available=1,.count=1,.ids={QCA6490_DEVICE_ID}};
  struct device_node root={.child=&high};high.next=&low;struct platform_device dev={.dev.of_node=&root};struct cnss_plat_data s={.dt_type=1,.plat_dev=&dev,.device_id=0x9999};
  gpio_present=1;gpio_number=83;gpio_value=0;gpio_reads=invalid_gpio_reads=updates=last_type=0;int want=0;unsigned long id=KIWI_DEVICE_ID;
  if(!strcmp(name,"high")||!strcmp(name,"reverse-high")||!strcmp(name,"missing-high-id")){gpio_value=1;id=QCA6490_DEVICE_ID;}
  if(!strncmp(name,"reverse",7)){root.child=&low;low.next=&high;high.next=NULL;}
  if(!strcmp(name,"non-converged")){s.dt_type=0;id=0x9999;}
  if(!strcmp(name,"missing-low-id")){low.ids[0]=0x1101;want=-EINVAL;}
  if(!strcmp(name,"missing-high-id")){high.ids[0]=0x1101;want=-EINVAL;}
  if(!strcmp(name,"empty-ids")){high.count=0;want=-EINVAL;}
  if(!strcmp(name,"property-read-error")){high.read_error=1;want=-EINVAL;}
  if(!strcmp(name,"unavailable-low")){low.available=0;want=-EINVAL;}
  if(!strcmp(name,"unrelated-name")){high.name="unrelated";}
  if(!strcmp(name,"no-children")){root.child=NULL;want=-EINVAL;}
  if(!strcmp(name,"missing-gpio-property")){gpio_present=0;}
  if(!strcmp(name,"deferred-gpio")){gpio_number=-517;}
  if(!strcmp(name,"negative-gpio-value")){gpio_value=-EINVAL;id=QCA6490_DEVICE_ID;}
  int result=cnss_get_dev_cfg_node(&s);assert(result==want);
  if(want){assert(s.device_id==0x9999&&updates==0&&s.plat_dev->dev.of_node==&root);}
  else{assert(s.device_id==id);if(s.dt_type==1)assert(updates==1&&last_type==(id==KIWI_DEVICE_ID?CNSS_HMT_DEVICE_TYPE:CNSS_HSP_DEVICE_TYPE));else assert(gpio_reads==0&&updates==0);}
  printf("{\"case\":\"%s\",\"return\":%d,\"source_selected_id\":%lu,\"gpio_reads_modeled\":%d,\"invalid_gpio_reads_modeled\":%d,\"native_operations\":0}\n",name,result,s.device_id,gpio_reads,invalid_gpio_reads);
 }
}
'''
unit=prefix+'\n'+getter+'\n'+selector+'\n'+suffix
(a.output/'selector-model.c').write_text(unit)
exe=a.output/'selector-model'
cmd=['cc','-std=c11','-O1','-g','-fsanitize=address,undefined',str(a.output/'selector-model.c'),'-o',str(exe)]
r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(exe)],capture_output=True,text=True);assert r.returncode==0,r.stdout+r.stderr
rows=[json.loads(line)for line in r.stdout.splitlines()]
x={'passed':True,'cases':len(rows),'exact_selector_source_sha256':sha(selector.encode()),'exact_getter_source_sha256':sha(getter.encode()),'main_source_sha256':sha(main),'power_source_sha256':sha(power),'sanitizers':['address','undefined behavior'],
   'models':['OF child availability/name/property access','GPIO lookup and sampled value','device-type notification'],
   'observations':['OEM source samples the selector before cnss_get_resources in its probe.','Low selects 1107/Kiwi and high selects 1103/QCA6490.','The getter returns zero even if the property is absent or GPIO lookup returns an error. The selector then calls the modeled GPIO API with that invalid number.','A negative modeled GPIO value becomes a nonzero u8. A future diagnostic must validate its input before interpreting a branch.'],
   'limits':['Original source bodies are host compiled; this does not prove the installed Android module uses this exact build.','GPIO/OF services and all sampled values are models; no physical GPIO or PCI identity is observed.','Invalid lookup/value outcomes expose missing validation boundaries, not a claim about a real kernel invalid-GPIO result.'],
   'native_operations':0,'results':rows}
(a.output/'results.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in['models','observations','limits','results']}))
