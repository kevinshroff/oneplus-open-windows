"""Exercise exact CNSS enumeration bodies with explicit property/PCI service models."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cnss-source',type=Path,required=True);p.add_argument('--platform-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
h=lambda b:hashlib.sha256(b).hexdigest();pci=(a.cnss_source/'pci.c').read_bytes();qcom=a.platform_source.read_bytes();header=(a.cnss_source/'pci.h').read_text();assert h(pci)=='7e96e571a709849619e885651bd09c74dfb5ca4aac94f5758c3f324e1f52f0ac'
assert h(qcom)=='370639840f6ce5e5f60e72eb8dcb3369b0d705f4adbd54caf8f9e14e9e394f14'
assert re.search(r'#define LINK_TRAINING_RETRY_MAX_TIMES\s+3',header)
def body(text,name):
 m=re.search(r'^(?:static )?int '+name+r'\(.*?^\}',text,re.M|re.S);assert m,name;return m[0]
fns=[body(qcom.decode(),n)for n in ['_cnss_pci_enumerate','cnss_pci_set_max_link_speed']]+[body(pci.decode(),n)for n in ['cnss_pci_enumerate','cnss_pci_init']]
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint32_t u32,__be32;typedef uint16_t u16;
#define QCA6490_DEVICE_ID 0x1103
#define EPROBE_DEFER 517
#define LINK_TRAINING_RETRY_MAX_TIMES 3
#define PCI_EXP_LNKSTA_CLS_5_0GB 2
#define cnss_pr_dbg(...) ((void)0)
#define cnss_pr_err(...) ((void)0)
struct device_node{int dummy;};struct device{struct device_node*of_node;};struct platform_device{struct device dev;};struct cnss_pci_data{int dummy;};
struct cnss_plat_data{u32 device_id,rc_num;void*bus_priv;struct platform_device*plat_dev;};
static int cnss_pci_driver;static struct cnss_plat_data*Current;
static __be32 RCs[2];static int PropLen,Missing,TrainErrors[8],TrainCount,SpeedError,RegisterError,NoProbe,Registers,Unregisters;static u32 Roots[8];
static char Events[256];
static void event(char c){size_t n=strlen(Events);assert(n+1<sizeof(Events));Events[n]=c;Events[n+1]=0;}
static int msm_pcie_enumerate(u32 rc){assert(TrainCount<8);Roots[TrainCount]=rc;event('E');return TrainErrors[TrainCount++];}
static int msm_pcie_set_target_link_speed(u32 rc,u16 speed,bool train){assert(rc<3&&speed==2&&!train);event('G');return SpeedError;}
static const __be32*of_get_property(struct device_node*n,const char*k,int*len){assert(n&&!strcmp(k,"qcom,wlan-rc-num"));*len=PropLen;return Missing?NULL:RCs;}
static u32 be32_to_cpup(const __be32*p){assert(p==RCs||p==RCs+1);return __builtin_bswap32(*p);}
static int pci_register_driver(int*p){assert(p==&cnss_pci_driver);event('R');Registers++;if(!RegisterError&&!NoProbe)Current->bus_priv=Current;return RegisterError;}
static void pci_unregister_driver(int*p){assert(p==&cnss_pci_driver);event('U');Unregisters++;}
'''
post=r'''
static struct device_node Node;static struct platform_device Device={{&Node}};static struct cnss_plat_data P;static unsigned Cases;
static void reset(void){memset(&P,0,sizeof(P));P.device_id=0x1107;P.rc_num=99;P.plat_dev=&Device;Current=&P;memset(TrainErrors,0,sizeof(TrainErrors));memset(Roots,0,sizeof(Roots));Events[0]=0;TrainCount=SpeedError=RegisterError=NoProbe=Registers=Unregisters=Missing=0;PropLen=4;RCs[0]=0;RCs[1]=__builtin_bswap32(1);}
static void check(const char*name,int result,int want,const char*events){assert(result==want&&!strcmp(Events,events));Cases++;printf("{\"case\":\"%s\",\"return\":%d,\"events\":\"%s\",\"enumerations\":%d,\"PCI_framework_registration\":%d}\n",name,result,Events,TrainCount,Registers);}
int main(void){
 reset();check("1107-root0",cnss_pci_init(&P),0,"ER");assert(P.rc_num==0&&Roots[0]==0);
 reset();P.device_id=0x1103;RCs[0]=__builtin_bswap32(1);check("1103-root1-gen2-request",cnss_pci_init(&P),0,"GER");assert(P.rc_num==1&&Roots[0]==1);
 reset();Missing=1;check("missing-RC-property-returns-zero-with-no-enumeration",cnss_pci_init(&P),0,"");assert(!P.bus_priv&&P.rc_num==99);
 reset();PropLen=0;check("empty-RC-property-returns-zero-with-no-enumeration",cnss_pci_init(&P),0,"");assert(!P.bus_priv&&P.rc_num==99);
 reset();PropLen=2;NoProbe=1;check("short-property-reaches-registration-without-enumeration",cnss_pci_init(&P),-ENODEV,"RU");assert(!TrainCount);
 reset();P.device_id=0x1103;SpeedError=-EINVAL;check("gen2-request-error-is-logged-but-enumeration-continues",cnss_pci_init(&P),0,"GER");
 reset();P.device_id=0x1103;SpeedError=-EPROBE_DEFER;check("gen2-request-defer-still-enumerates",cnss_pci_init(&P),0,"GER");
 reset();TrainErrors[0]=-EPROBE_DEFER;check("root-not-ready-no-retry",cnss_pci_init(&P),-EPROBE_DEFER,"E");assert(P.rc_num==99);
 for(unsigned tries=1;tries<4;tries++){reset();for(unsigned i=0;i<tries;i++)TrainErrors[i]=-ENODEV;char want[8]={0};memset(want,'E',tries+1);want[tries+1]='R';check("bounded-retry-before-success",cnss_pci_init(&P),0,want);assert(TrainCount==(int)tries+1);}
 reset();for(unsigned i=0;i<4;i++)TrainErrors[i]=-ENODEV;check("four-failed-link-attempts",cnss_pci_init(&P),-ENODEV,"EEEE");assert(!Registers&&P.rc_num==99);
 reset();PropLen=8;for(unsigned i=0;i<4;i++)TrainErrors[i]=-ENODEV;check("second-root-after-first-exhausts",cnss_pci_init(&P),0,"EEEEER");assert(P.rc_num==1&&Roots[4]==1);
 reset();PropLen=8;TrainErrors[0]=-EPROBE_DEFER;check("defer-does-not-try-another-root",cnss_pci_init(&P),-EPROBE_DEFER,"E");
 reset();RegisterError=-EINVAL;check("framework-registration-error",cnss_pci_init(&P),-EINVAL,"ER");assert(P.rc_num==0&&!P.bus_priv&&!Unregisters);
 reset();NoProbe=1;check("no-PCI-probe-unregisters",cnss_pci_init(&P),-ENODEV,"ERU");assert(Unregisters==1);
 reset();RCs[0]=__builtin_bswap32(2);check("wrapper-forwards-unvalidated-root-index",cnss_pci_init(&P),0,"ER");assert(Roots[0]==2);
 fprintf(stderr,"cases=%u\n",Cases);
}
'''
f=a.output/'model.c';f.write_text(pre+'\n'.join(fns)+post);exe=a.output/'test'
r=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(f),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr
r=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not r.returncode,(r.stdout,r.stderr);rows=[json.loads(line)for line in r.stdout.splitlines()];assert r.stderr==f'cases={len(rows)}\n'
v={'passed':True,'cases':len(rows),'results':rows,'pci_source_sha256':h(pci),'platform_source_sha256':h(qcom),'original_function_body_sha256':{name:h(fn.encode())for name,fn in zip(['_cnss_pci_enumerate','cnss_pci_set_max_link_speed','cnss_pci_enumerate','cnss_pci_init'],fns)},'sanitizers':['ASAN','UBSan'],'models':['OF properties','MSM root enumeration and Gen2 request','PCI registration/probe side effect'],'limits':['No Linux kernel runs; no hardware root enumerates.','A zero CNSS helper return alone does not establish property availability, enumeration, a Gen2 speed or endpoint identity.','The wrapper forwards RC index to an explicit model; no out-of-range real root access occurred.'],'native_operations':0}
(a.output/'results.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'native_operations':0,'platform_source_sha256':h(qcom)}))
